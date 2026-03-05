use exhume_body::Body;
use exhume_filesystem::detected_fs::{detect_filesystem, KeyMaterial};
use exhume_filesystem::folder_impl::FolderFS;
use exhume_filesystem::{File, Filesystem};
use sqlx::sqlite::SqlitePool;
use sqlx::types::Json;
use std::path::PathBuf;
use tokio::sync::mpsc::Sender;
use tracing::{error, info};

pub mod artifacts;
pub mod identification;

#[derive(Debug, Clone)]
pub enum IndexerEventType {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct IndexerEvent {
    pub evidence_id: i64,
    pub event_type: IndexerEventType,
    pub message: String,
}

/// Helper to optionally send progress
async fn send_progress(tx: &Option<Sender<IndexerEvent>>, event: IndexerEvent) {
    if let Some(sender) = tx {
        let _ = sender.send(event).await;
    }
}

pub async fn index_filesystem<T: Filesystem>(
    fs: &mut T,
    evidence_id: i64,
    partition_id: i64,
    pool: &SqlitePool,
    tx_progress: Option<Sender<IndexerEvent>>,
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
    .await {
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
        ).await;
        error!("{}", msg);
        return;
    }

    let mut files = Vec::<File>::new();
    let mut discovered = 0;
    
    let tx_clone = tx_progress.clone();
    let walk_err = match fs.walk_fs(&mut |event| match event {
        exhume_filesystem::filesystem::WalkEvent::File(f) => {
            files.push(f);
            discovered += 1;
            if discovered % 1000 == 0 {
                if let Some(sender) = &tx_clone {
                    let _ = sender.try_send(IndexerEvent {
                        evidence_id,
                        event_type: IndexerEventType::Info,
                        message: format!("Discovered {} files", discovered),
                    });
                }
            }
        },
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
        send_progress(&tx_progress, IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Error,
            message: msg.clone(),
        }).await;
        error!("{}", msg);
        return;
    }

    send_progress(&tx_progress, IndexerEvent {
        evidence_id,
        event_type: IndexerEventType::Info,
        message: "Ingesting files into the database…".to_string(),
    }).await;

    let total = files.len() as u64;
    let mut inserted = 0u64;

    let tx_obj = match pool.begin().await {
        Ok(t) => Some(t),
        Err(e) => {
            let msg = format!("Could not open DB transaction: {e:?}");
            send_progress(&tx_progress, IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Error,
                message: msg.clone(),
            }).await;
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
            metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    "#;

    for f in &files {
        let created = f.created.unwrap_or(0) as i64;
        let modified = f.modified.unwrap_or(0) as i64;
        let accessed = f.accessed.unwrap_or(0) as i64;

        let insert_err = match sqlx::query(stmt)
            .bind(evidence_id)
            .bind(partition_id)
            .bind(f.identifier as i64)
            .bind(&f.absolute_path)
            .bind(&f.name)
            .bind(&f.ftype)
            .bind(f.size as i64)
            .bind(Some(created))
            .bind(Some(modified))
            .bind(Some(accessed))
            .bind(&f.permissions)
            .bind(&f.owner)
            .bind(&f.group)
            .bind(&f.display)
            .bind(Json(&f.metadata))
            .execute(&mut *tx)
            .await 
        {
            Ok(_) => None,
            Err(e) => Some(format!("Insert error: {e:?}")),
        };

        if let Some(msg) = insert_err {
            send_progress(&tx_progress, IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Error,
                message: msg.clone(),
            }).await;
            error!("{}", msg);
        }

        inserted += 1;
        if inserted % 500 == 0 || inserted == total {
            send_progress(&tx_progress, IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Info,
                message: format!("Indexed {inserted}/{total} items…"),
            }).await;
        }
    }

    let commit_err = match tx.commit().await {
        Ok(_) => None,
        Err(e) => Some(format!("Commit error: {e:?}")),
    };

    if let Some(msg) = commit_err {
        send_progress(&tx_progress, IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Error,
            message: msg.clone(),
        }).await;
        error!("{}", msg);
        return;
    }

    send_progress(&tx_progress, IndexerEvent {
        evidence_id,
        event_type: IndexerEventType::Success,
        message: format!("Successfully ingested {total} items into the database."),
    }).await;
}

pub async fn index_partition(
    evidence_id: i64,
    partition_id: i64,
    size_sectors: u64,
    first_byte_addr: u64,
    disk_image_path: String,
    pool: &SqlitePool,
    tx_progress: Option<Sender<IndexerEvent>>,
) {
    let mut body = Body::new(disk_image_path, "auto");
    let sector_size = body.get_sector_size() as u64;
    let partition_size_bytes = size_sectors * sector_size;

    let partition_fvek_result: Option<String> = sqlx::query_scalar("SELECT fvek FROM mbr_partition_entries WHERE id = ? UNION SELECT fvek FROM gpt_partition_entries WHERE id = ? UNION SELECT fvek FROM logical_partition_entries WHERE id = ? LIMIT 1")
    .bind(partition_id)
    .bind(partition_id)
    .bind(partition_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let key_material = partition_fvek_result.and_then(|h| hex::decode(h).ok()).map(|fvek| KeyMaterial { bitlocker_fvek: Some(fvek) });

    let (fs_opt, err_msg) = match detect_filesystem(&mut body, first_byte_addr, partition_size_bytes, key_material) {
        Ok(fs) => (Some(fs), None),
        Err(err) => (None, Some(format!("Could not detect the filesystem: {}", err))),
    };

    if let Some(msg) = err_msg {
        send_progress(&tx_progress, IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Error,
            message: msg.clone(),
        }).await;
        error!("{}", msg);
        return;
    }

    let mut fs = fs_opt.unwrap();
    index_filesystem(&mut fs, evidence_id, partition_id, pool, tx_progress).await
}

pub async fn index_folder(
    evidence_id: i64,
    partition_id: i64,
    folder_path: String,
    pool: &SqlitePool,
    tx_progress: Option<Sender<IndexerEvent>>,
) {
    let path = PathBuf::from(folder_path);
    let mut fs = FolderFS::new(path);
    index_filesystem(&mut fs, evidence_id, partition_id, pool, tx_progress).await
}
