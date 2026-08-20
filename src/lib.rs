use exhume_body::Body;
use exhume_filesystem::detected_fs::{detect_filesystem, KeyMaterial};
use exhume_filesystem::folder_impl::FolderFS;
use exhume_filesystem::{File, Filesystem};
use sqlx::sqlite::SqlitePool;
use sqlx::types::Json;
use sqlx::Row;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::{error, info};

pub mod artifacts;
pub mod identification;

/// The raw YAML source for the artifact catalog, embedded at compile time.
/// Consumers can parse it with `ArtifactSet::from_yaml_str`.
pub const ARTIFACTS_YAML: &str = include_str!("../artifacts.yaml");

#[derive(Debug, Clone)]
pub enum IndexerEventType {
    Info,
    Progress {
        current: u64,
        total: u64,
    },
    ParserProgress {
        current: u64,
        total: u64,
        parser: String,
        file_path: String,
        artifact_id: i64,
        file_id: Option<i64>,
        phase: ParserProgressPhase,
        elapsed_ms: Option<u64>,
        setup_ms: Option<u64>,
        parse_ms: Option<u64>,
        persistence_ms: Option<u64>,
        objects_emitted: Option<u64>,
    },
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserProgressPhase {
    Started,
    Completed,
    Failed,
}

impl ParserProgressPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct IndexerEvent {
    pub evidence_id: i64,
    pub event_type: IndexerEventType,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionKind {
    Mbr,
    Gpt,
    Logical,
    Folder,
}

impl PartitionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mbr => "mbr",
            Self::Gpt => "gpt",
            Self::Logical => "logical",
            Self::Folder => "folder",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PartitionRecord {
    pub id: i64,
    pub evidence_id: i64,
    pub kind: PartitionKind,
    pub first_byte_addr: u64,
    pub size_sectors: u64,
    pub sector_size: u64,
    pub size_bytes: u64,
    pub fvek: Option<String>,
}

/// Helper to optionally send progress
async fn send_progress(tx: &Option<Sender<IndexerEvent>>, event: IndexerEvent) {
    if let Some(sender) = tx {
        let _ = sender.send(event).await;
    }
}

fn normalize_path_key(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();

    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn compute_parent_path_key(path_key: &str) -> Option<String> {
    if path_key == "/" {
        return None;
    }

    match path_key.rsplit_once('/') {
        Some(("", _)) => Some("/".to_string()),
        Some((parent, _)) => Some(parent.to_string()),
        None => Some("/".to_string()),
    }
}

fn compute_depth(path_key: &str) -> i64 {
    if path_key == "/" {
        0
    } else {
        path_key
            .split('/')
            .filter(|segment| !segment.is_empty())
            .count() as i64
    }
}

fn is_directory_type(ftype: &str) -> bool {
    matches!(ftype.to_ascii_lowercase().as_str(), "dir" | "directory")
}

pub async fn ensure_evidence_row(
    pool: &SqlitePool,
    evidence_id: i64,
    path: &str,
    is_folder: bool,
) -> Result<(), sqlx::Error> {
    let name = PathBuf::from(path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(path)
        .to_string();
    let kind = if is_folder {
        "Folder"
    } else {
        "Logical Disk image"
    };

    sqlx::query(
        r#"
        INSERT INTO evidence (id, case_id, name, type, path, description, status)
        VALUES (?, NULL, ?, ?, ?, '', 0)
        ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            type = excluded.type,
            path = excluded.path
        "#,
    )
    .bind(evidence_id)
    .bind(name)
    .bind(kind)
    .bind(path)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn insert_partition(
    pool: &SqlitePool,
    evidence_id: i64,
    kind: PartitionKind,
    first_byte_addr: u64,
    size_sectors: u64,
    sector_size: u64,
    size_bytes: u64,
    fvek: Option<&str>,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(
        r#"
        INSERT INTO partitions (
            evidence_id,
            kind,
            first_byte_addr,
            size_sectors,
            sector_size,
            size_bytes,
            fvek
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        RETURNING id
        "#,
    )
    .bind(evidence_id)
    .bind(kind.as_str())
    .bind(first_byte_addr as i64)
    .bind(size_sectors as i64)
    .bind(sector_size as i64)
    .bind(size_bytes as i64)
    .bind(fvek)
    .fetch_one(pool)
    .await?;

    Ok(row.get(0))
}

pub async fn update_partition(
    pool: &SqlitePool,
    partition_id: i64,
    first_byte_addr: u64,
    size_sectors: u64,
    sector_size: u64,
    size_bytes: u64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE partitions
        SET first_byte_addr = ?,
            size_sectors = ?,
            sector_size = ?,
            size_bytes = ?
        WHERE id = ?
        "#,
    )
    .bind(first_byte_addr as i64)
    .bind(size_sectors as i64)
    .bind(sector_size as i64)
    .bind(size_bytes as i64)
    .bind(partition_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_partition(
    pool: &SqlitePool,
    partition_id: i64,
) -> Result<Option<PartitionRecord>, sqlx::Error> {
    let row = sqlx::query(
        r#"
        SELECT id, evidence_id, kind, first_byte_addr, size_sectors, sector_size, size_bytes, fvek
        FROM partitions
        WHERE id = ?
        "#,
    )
    .bind(partition_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| PartitionRecord {
        id: row.get("id"),
        evidence_id: row.get("evidence_id"),
        kind: match row.get::<String, _>("kind").as_str() {
            "mbr" => PartitionKind::Mbr,
            "gpt" => PartitionKind::Gpt,
            "folder" => PartitionKind::Folder,
            _ => PartitionKind::Logical,
        },
        first_byte_addr: row.get::<i64, _>("first_byte_addr") as u64,
        size_sectors: row.get::<i64, _>("size_sectors") as u64,
        sector_size: row.get::<i64, _>("sector_size") as u64,
        size_bytes: row.get::<i64, _>("size_bytes") as u64,
        fvek: row.try_get("fvek").ok(),
    }))
}

pub async fn list_partitions(
    pool: &SqlitePool,
    evidence_id: i64,
) -> Result<Vec<PartitionRecord>, sqlx::Error> {
    let rows = sqlx::query(
        r#"
        SELECT id, evidence_id, kind, first_byte_addr, size_sectors, sector_size, size_bytes, fvek
        FROM partitions
        WHERE evidence_id = ?
        ORDER BY id
        "#,
    )
    .bind(evidence_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| PartitionRecord {
            id: row.get("id"),
            evidence_id: row.get("evidence_id"),
            kind: match row.get::<String, _>("kind").as_str() {
                "mbr" => PartitionKind::Mbr,
                "gpt" => PartitionKind::Gpt,
                "folder" => PartitionKind::Folder,
                _ => PartitionKind::Logical,
            },
            first_byte_addr: row.get::<i64, _>("first_byte_addr") as u64,
            size_sectors: row.get::<i64, _>("size_sectors") as u64,
            sector_size: row.get::<i64, _>("sector_size") as u64,
            size_bytes: row.get::<i64, _>("size_bytes") as u64,
            fvek: row.try_get("fvek").ok(),
        })
        .collect())
}

/// Populate `timeline_events` with filesystem timestamp entries for a partition.
///
/// Inserts one row per non-null `created`, `modified`, and `accessed` timestamp
/// from `system_files`, converting seconds to milliseconds. Existing filesystem
/// entries for this partition are replaced on each call (idempotent).
pub async fn populate_filesystem_timeline(
    evidence_id: i64,
    partition_id: i64,
    pool: &SqlitePool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM timeline_events WHERE evidence_id = ? AND partition_id = ? AND source = 'filesystem'",
    )
    .bind(evidence_id)
    .bind(partition_id)
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO timeline_events (evidence_id, partition_id, ts, source, event_type, description, file_id)
        SELECT evidence_id, partition_id, created * 1000, 'filesystem', 'file.created', name, id
        FROM system_files
        WHERE evidence_id = ? AND partition_id = ? AND created IS NOT NULL AND is_dir = 0
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO timeline_events (evidence_id, partition_id, ts, source, event_type, description, file_id)
        SELECT evidence_id, partition_id, modified * 1000, 'filesystem', 'file.modified', name, id
        FROM system_files
        WHERE evidence_id = ? AND partition_id = ? AND modified IS NOT NULL AND is_dir = 0
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO timeline_events (evidence_id, partition_id, ts, source, event_type, description, file_id)
        SELECT evidence_id, partition_id, accessed * 1000, 'filesystem', 'file.accessed', name, id
        FROM system_files
        WHERE evidence_id = ? AND partition_id = ? AND accessed IS NOT NULL AND is_dir = 0
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn index_filesystem<T: Filesystem>(
    fs: &mut T,
    evidence_id: i64,
    partition_id: i64,
    pool: &SqlitePool,
    tx_progress: Option<Sender<IndexerEvent>>,
    cancel_token: Option<Arc<AtomicBool>>,
    // For folder evidence: the host filesystem root stored in `host_path` for shell operations.
    // Pass None for disk image partitions (no direct host path mapping exists).
    path_prefix: Option<&str>,
) {
    info!("Starting filesystem indexation…");

    let prepare_err = match sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_files_identifier
            ON system_files(identifier);
        CREATE INDEX IF NOT EXISTS idx_files_ev_path
            ON system_files(evidence_id, absolute_path);
        "#,
    )
    .execute(pool)
    .await
    {
        Ok(_) => None,
        Err(e) => Some(format!("Could not prepare DB: {e:?}")),
    };

    if let Some(msg) = prepare_err {
        send_progress(
            &tx_progress,
            IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Error,
                message: msg.clone(),
            },
        )
        .await;
        error!("{}", msg);
        return;
    }

    let mut files = Vec::<File>::new();
    let mut discovered = 0;

    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Progress {
                current: 0,
                total: 0,
            },
            message: "Discovering files in the filesystem…".to_string(),
        },
    )
    .await;

    let tx_clone = tx_progress.clone();
    let walk_err = match fs.walk_fs(&mut |event| match event {
        exhume_filesystem::filesystem::WalkEvent::File(f) => {
            files.push(f);
            discovered += 1;
            if discovered <= 20 || discovered % 25 == 0 {
                if let Some(sender) = &tx_clone {
                    let _ = sender.try_send(IndexerEvent {
                        evidence_id,
                        event_type: IndexerEventType::Progress {
                            current: discovered,
                            total: 0,
                        },
                        message: format!("Discovering files… {discovered} found so far."),
                    });
                }
            }
        }
        exhume_filesystem::filesystem::WalkEvent::Status(msg) => {
            if let Some(sender) = &tx_clone {
                let _ = sender.try_send(IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Info,
                    message: msg,
                });
            }
        }
    }) {
        Ok(_) => None,
        Err(e) => Some(format!("Failed to walk filesystem: {e}")),
    };

    if let Some(msg) = walk_err {
        send_progress(
            &tx_progress,
            IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Error,
                message: msg.clone(),
            },
        )
        .await;
        error!("{}", msg);
        return;
    }

    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Info,
            message: format!("Discovery complete. {discovered} files found."),
        },
    )
    .await;

    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Info,
            message: "Ingesting files into the database…".to_string(),
        },
    )
    .await;

    let total = files.len() as u64;
    let mut inserted = 0u64;

    let tx_obj = match pool.begin().await {
        Ok(t) => Some(t),
        Err(e) => {
            let msg = format!("Could not open DB transaction: {e:?}");
            send_progress(
                &tx_progress,
                IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Error,
                    message: msg.clone(),
                },
            )
            .await;
            error!("{}", msg);
            None
        }
    };

    let mut tx = match tx_obj {
        Some(t) => t,
        None => return,
    };

    let stmt = r#"
        INSERT INTO system_files (
            evidence_id,
            partition_id,
            identifier,
            absolute_path,
            name,
            ftype,
            size,
            created,
            modified,
            accessed,
            permissions,
            owner,
            "group",
            display,
            path_key,
            parent_path_key,
            depth,
            is_dir,
            sig_name,
            sig_mime,
            sig_exts,
            host_path,
            metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    "#;

    for f in &files {
        if let Some(token) = &cancel_token {
            if token.load(Ordering::Relaxed) {
                // Abort processing without committing.
                return;
            }
        }

        let created = f.created.map(|value| value as i64);
        let modified = f.modified.map(|value| value as i64);
        let accessed = f.accessed.map(|value| value as i64);
        let path_key = normalize_path_key(&f.absolute_path);
        let parent_path_key = compute_parent_path_key(&path_key);
        let depth = compute_depth(&path_key);
        let is_dir = if is_directory_type(&f.ftype) {
            1i64
        } else {
            0i64
        };

        // For folder evidence, compute the real host filesystem path.
        // absolute_path stays as the logical forensic path (used by artifact pattern matching).
        // host_path is what the agent should use for shell operations.
        let host_path: Option<String> = path_prefix.map(|prefix| {
            let p = prefix.trim_end_matches('/');
            if f.absolute_path == "/" || f.absolute_path.is_empty() {
                p.to_string()
            } else {
                format!("{}{}", p, f.absolute_path)
            }
        });

        let insert_err = match sqlx::query(stmt)
            .bind(evidence_id)
            .bind(partition_id)
            .bind(f.identifier as i64)
            .bind(&f.absolute_path)
            .bind(&f.name)
            .bind(&f.ftype)
            .bind(f.size as i64)
            .bind(created)
            .bind(modified)
            .bind(accessed)
            .bind(&f.permissions)
            .bind(&f.owner)
            .bind(&f.group)
            .bind(&f.display)
            .bind(&path_key)
            .bind(&parent_path_key)
            .bind(depth)
            .bind(is_dir)
            .bind(Option::<String>::None)
            .bind(Option::<String>::None)
            .bind(Option::<String>::None)
            .bind(host_path)
            .bind(Json(&f.metadata))
            .execute(&mut *tx)
            .await
        {
            Ok(_) => None,
            Err(e) => Some(format!("Insert error: {e:?}")),
        };

        if let Some(msg) = insert_err {
            send_progress(
                &tx_progress,
                IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Error,
                    message: msg.clone(),
                },
            )
            .await;
            error!("{}", msg);
        }

        inserted += 1;
        if inserted % 500 == 0 || inserted == total {
            send_progress(
                &tx_progress,
                IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Progress {
                        current: inserted,
                        total,
                    },
                    message: format!("Indexed {inserted}/{total} items…"),
                },
            )
            .await;
        }
    }

    let commit_err = match tx.commit().await {
        Ok(_) => None,
        Err(e) => Some(format!("Commit error: {e:?}")),
    };

    if let Some(msg) = commit_err {
        send_progress(
            &tx_progress,
            IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Error,
                message: msg.clone(),
            },
        )
        .await;
        error!("{}", msg);
        return;
    }

    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Success,
            message: format!("Successfully ingested {total} items into the database."),
        },
    )
    .await;
}

pub async fn index_partition(
    evidence_id: i64,
    partition_id: i64,
    size_sectors: u64,
    first_byte_addr: u64,
    disk_image_path: String,
    pool: &SqlitePool,
    tx_progress: Option<Sender<IndexerEvent>>,
    cancel_token: Option<Arc<AtomicBool>>,
) -> Result<(), Box<dyn std::error::Error>> {
    index_partition_with_format(
        evidence_id,
        partition_id,
        size_sectors,
        first_byte_addr,
        disk_image_path,
        "auto",
        pool,
        tx_progress,
        cancel_token,
    )
    .await
}

pub async fn index_partition_with_format(
    evidence_id: i64,
    partition_id: i64,
    size_sectors: u64,
    first_byte_addr: u64,
    disk_image_path: String,
    body_format: &str,
    pool: &SqlitePool,
    tx_progress: Option<Sender<IndexerEvent>>,
    cancel_token: Option<Arc<AtomicBool>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut body = Body::new(disk_image_path, body_format);
    let sector_size = body.get_sector_size() as u64;
    let partition_size_bytes = size_sectors * sector_size;

    let partition_fvek_result = get_partition(pool, partition_id)
        .await
        .ok()
        .flatten()
        .and_then(|partition| partition.fvek);

    let key_material = partition_fvek_result
        .and_then(|h| hex::decode(h).ok())
        .map(|fvek| KeyMaterial {
            bitlocker_fvek: Some(fvek),
        });

    let mut fs = detect_filesystem(
        &mut body,
        first_byte_addr,
        partition_size_bytes,
        key_material,
    )?;

    index_filesystem(
        &mut fs,
        evidence_id,
        partition_id,
        pool,
        tx_progress,
        cancel_token,
        None, // disk image partitions have no direct host path mapping
    )
    .await;
    Ok(())
}

pub async fn index_folder(
    evidence_id: i64,
    partition_id: i64,
    folder_path: String,
    pool: &SqlitePool,
    tx_progress: Option<Sender<IndexerEvent>>,
    cancel_token: Option<Arc<AtomicBool>>,
) {
    let path = PathBuf::from(&folder_path);
    let mut fs = FolderFS::new(path);
    index_filesystem(
        &mut fs,
        evidence_id,
        partition_id,
        pool,
        tx_progress,
        cancel_token,
        Some(&folder_path),
    )
    .await
}

pub async fn ensure_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS evidence (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     INTEGER,
            name        TEXT NOT NULL,
            type        TEXT NOT NULL,
            path        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            status      INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS partitions (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id         INTEGER NOT NULL,
            kind                TEXT NOT NULL CHECK (kind IN ('mbr', 'gpt', 'logical', 'folder')),
            first_byte_addr     INTEGER NOT NULL DEFAULT 0,
            size_sectors        INTEGER NOT NULL DEFAULT 0,
            sector_size         INTEGER NOT NULL DEFAULT 512,
            size_bytes          INTEGER NOT NULL DEFAULT 0,
            start_lba           INTEGER,
            end_lba             INTEGER,
            partition_guid      TEXT,
            partition_type_guid TEXT,
            partition_name      TEXT,
            partition_type      INTEGER,
            boot_indicator      INTEGER,
            start_chs           BLOB,
            end_chs             BLOB,
            attributes          INTEGER,
            description         TEXT NOT NULL DEFAULT '',
            fvek                TEXT
        );

        CREATE TABLE IF NOT EXISTS system_files (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id     INTEGER NOT NULL,
            partition_id    INTEGER NOT NULL,
            identifier      INTEGER NOT NULL,
            absolute_path   TEXT    NOT NULL,
            name            TEXT    NOT NULL,
            ftype           TEXT    NOT NULL,
            size            INTEGER NOT NULL,
            created         INTEGER,
            modified        INTEGER,
            accessed        INTEGER,
            permissions     TEXT,
            owner           TEXT,
            "group"         TEXT,
            display         TEXT,
            path_key        TEXT    NOT NULL,
            parent_path_key TEXT,
            depth           INTEGER NOT NULL DEFAULT 0,
            is_dir          INTEGER NOT NULL DEFAULT 0,
            sig_name        TEXT,
            sig_mime        TEXT,
            sig_exts        TEXT,
            anomaly_flag    INTEGER,
            host_path       TEXT,
            metadata        JSON    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS artifacts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id     INTEGER NOT NULL,
            file_id         INTEGER NOT NULL,
            partition_id    INTEGER NOT NULL,
            name            TEXT NOT NULL,
            description     TEXT NOT NULL,
            parser          TEXT,
            tag             TEXT NOT NULL,
            category        TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS artifact_objects (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id     INTEGER NOT NULL,
            partition_id    INTEGER NOT NULL,
            artifact_id     INTEGER NOT NULL,
            file_id         INTEGER,
            parser          TEXT NOT NULL,
            kind            TEXT NOT NULL,
            text            TEXT,
            json            TEXT NOT NULL,
            created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );

        CREATE TABLE IF NOT EXISTS timeline_events (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id          INTEGER NOT NULL,
            partition_id         INTEGER NOT NULL,
            ts                   INTEGER NOT NULL,
            source               TEXT NOT NULL,
            event_type           TEXT NOT NULL,
            description          TEXT,
            file_id              INTEGER,
            artifact_object_id   INTEGER,
            actor                TEXT
        );

        CREATE TABLE IF NOT EXISTS artifact_attachment_refs (
            id                     INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id            INTEGER NOT NULL,
            partition_id           INTEGER NOT NULL,
            artifact_object_id     INTEGER NOT NULL,
            parser                 TEXT NOT NULL,
            app                    TEXT,
            platform               TEXT,
            media_rowid            INTEGER,
            message_rowid          INTEGER,
            chat_rowid             INTEGER,
            local_path             TEXT,
            thumbnail_local_path   TEXT,
            remote_url             TEXT,
            title                  TEXT,
            kind                   TEXT,
            mime                   TEXT,
            file_name              TEXT,
            file_size              INTEGER,
            duration_seconds       REAL,
            width                  INTEGER,
            height                 INTEGER,
            latitude               REAL,
            longitude              REAL,
            resolved_file_id       INTEGER,
            resolved_fs_identifier INTEGER,
            resolved_absolute_path TEXT,
            resolved_host_path     TEXT,
            resolved_sig_mime      TEXT,
            resolved_name          TEXT,
            resolved_size          INTEGER,
            preview_mime           TEXT,
            preview_base64         TEXT,
            json                   TEXT NOT NULL,
            created_at             INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_partitions_evidence
            ON partitions (evidence_id, kind);
        CREATE INDEX IF NOT EXISTS idx_sysfiles_ev_part
            ON system_files (evidence_id, partition_id);
        CREATE INDEX IF NOT EXISTS idx_sysfiles_created
            ON system_files (created);
        CREATE INDEX IF NOT EXISTS idx_sysfiles_accessed
            ON system_files (accessed);
        CREATE INDEX IF NOT EXISTS idx_sysfiles_modified
            ON system_files (modified);
        CREATE INDEX IF NOT EXISTS idx_sysfiles_tree_path
            ON system_files (evidence_id, partition_id, path_key);
        CREATE INDEX IF NOT EXISTS idx_sysfiles_tree_parent
            ON system_files (evidence_id, partition_id, parent_path_key, is_dir, name);
        CREATE INDEX IF NOT EXISTS idx_sysfiles_anomaly
            ON system_files (anomaly_flag) WHERE anomaly_flag IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_artifact_objects_evp
            ON artifact_objects (evidence_id, partition_id);
        CREATE INDEX IF NOT EXISTS idx_artifact_objects_artifact
            ON artifact_objects (artifact_id);
        CREATE INDEX IF NOT EXISTS idx_artifact_objects_file
            ON artifact_objects (file_id);
        CREATE INDEX IF NOT EXISTS idx_artifact_objects_scope_file_id
            ON artifact_objects (evidence_id, partition_id, file_id, id);
        CREATE INDEX IF NOT EXISTS idx_artifact_objects_parser_kind
            ON artifact_objects (parser, kind);
        CREATE INDEX IF NOT EXISTS idx_artifact_objects_scope_parser_kind
            ON artifact_objects (evidence_id, partition_id, parser, kind, id);
        CREATE INDEX IF NOT EXISTS idx_artifact_objects_scope_kind
            ON artifact_objects (evidence_id, partition_id, kind, artifact_id, id);
        CREATE INDEX IF NOT EXISTS idx_artifacts_scope_category_tag_parser
            ON artifacts (evidence_id, partition_id, category, tag, parser, id);
        CREATE INDEX IF NOT EXISTS idx_attachment_refs_message
            ON artifact_attachment_refs (evidence_id, partition_id, parser, message_rowid);
        CREATE INDEX IF NOT EXISTS idx_attachment_refs_chat
            ON artifact_attachment_refs (evidence_id, partition_id, parser, chat_rowid);
        CREATE INDEX IF NOT EXISTS idx_attachment_refs_object
            ON artifact_attachment_refs (artifact_object_id);
        CREATE INDEX IF NOT EXISTS idx_timeline_events_ev_part
            ON timeline_events (evidence_id, partition_id, ts);
        CREATE INDEX IF NOT EXISTS idx_timeline_events_source
            ON timeline_events (evidence_id, partition_id, source, event_type);
        "#,
    )
    .execute(pool)
    .await?;

    // Unified timeline view: all filesystem timestamps in a single queryable surface
    sqlx::query(
        r#"
        CREATE VIEW IF NOT EXISTS timeline AS
        SELECT
            sf.evidence_id,
            sf.partition_id,
            sf.id          AS row_id,
            sf.identifier,
            sf.absolute_path,
            sf.host_path,
            sf.name,
            sf.sig_name,
            sf.anomaly_flag,
            'created'      AS event_type,
            datetime(sf.created, 'unixepoch') AS event_time,
            sf.created     AS ts_unix
        FROM system_files sf
        WHERE sf.created IS NOT NULL AND sf.is_dir = 0
        UNION ALL
        SELECT
            sf.evidence_id,
            sf.partition_id,
            sf.id,
            sf.identifier,
            sf.absolute_path,
            sf.host_path,
            sf.name,
            sf.sig_name,
            sf.anomaly_flag,
            'modified',
            datetime(sf.modified, 'unixepoch'),
            sf.modified
        FROM system_files sf
        WHERE sf.modified IS NOT NULL AND sf.is_dir = 0
        UNION ALL
        SELECT
            sf.evidence_id,
            sf.partition_id,
            sf.id,
            sf.identifier,
            sf.absolute_path,
            sf.host_path,
            sf.name,
            sf.sig_name,
            sf.anomaly_flag,
            'accessed',
            datetime(sf.accessed, 'unixepoch'),
            sf.accessed
        FROM system_files sf
        WHERE sf.accessed IS NOT NULL AND sf.is_dir = 0
        ORDER BY ts_unix;
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
