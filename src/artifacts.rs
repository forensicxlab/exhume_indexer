use anyhow::Result;
use exhume_artefacts::parsers::ParserRegistry;
use exhume_artefacts::{ObjectParsed, Parser as ArtefactParser, ParserInput};
use exhume_filesystem::filesystem::{FileCommon, FsFileReadSeek};
use exhume_filesystem::File;
use exhume_filesystem::Filesystem;
use regex::escape;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::{error, info};

use crate::{send_progress, IndexerEvent, IndexerEventType};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    System,
    Network,
    Users,
    Media,
    Application,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ArtifactPath {
    Literal(String),
    WithFlag {
        path: String,
        #[serde(default)]
        regexp: bool,
    },
}

impl ArtifactPath {
    pub fn to_regex(&self) -> String {
        match self {
            ArtifactPath::Literal(p) => {
                format!("^{}$", escape(p))
            }
            ArtifactPath::WithFlag { path, regexp } => {
                if *regexp {
                    path.clone()
                } else {
                    format!("^{}$", escape(path))
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    pub description: String,
    pub paths: Vec<ArtifactPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parser: Option<String>,
    pub tag: String,
    pub category: Category,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactSet {
    pub artifacts: Vec<Artifact>,
}

impl ArtifactSet {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }
}

fn decode_system_file_row(row: &sqlx::sqlite::SqliteRow) -> Result<File, sqlx::Error> {
    Ok(File {
        id: row.try_get("id")?,
        // SQLite stores INTEGER as signed i64. Reinterpret wrapped values so
        // folder-backed identifiers above i64::MAX round-trip correctly.
        identifier: row.try_get::<i64, _>("identifier")? as u64,
        absolute_path: row.try_get("absolute_path")?,
        name: row.try_get("name")?,
        ftype: row.try_get("ftype")?,
        size: row.try_get::<i64, _>("size")? as u64,
        created: row
            .try_get::<Option<i64>, _>("created")?
            .map(|value| value as u64),
        modified: row
            .try_get::<Option<i64>, _>("modified")?
            .map(|value| value as u64),
        accessed: row
            .try_get::<Option<i64>, _>("accessed")?
            .map(|value| value as u64),
        permissions: row.try_get("permissions")?,
        owner: row.try_get("owner")?,
        group: row.try_get("group")?,
        display: row.try_get("display")?,
        sig_name: row.try_get("sig_name")?,
        sig_mime: row.try_get("sig_mime")?,
        sig_exts: row.try_get("sig_exts")?,
        metadata: row.try_get("metadata")?,
    })
}

#[cfg(test)]
mod tests {
    use super::ArtifactSet;

    #[test]
    fn embedded_artifacts_yaml_parses() {
        let yaml = include_str!("../artifacts.yaml");
        let artifact_set =
            ArtifactSet::from_yaml_str(yaml).expect("embedded artifacts.yaml should parse");
        assert!(
            !artifact_set.artifacts.is_empty(),
            "embedded artifacts.yaml should contain entries"
        );
    }
}

pub async fn identify_artefacts(
    evidence_id: i64,
    partition_id: i64,
    pool: &SqlitePool,
    tx_progress: Option<Sender<IndexerEvent>>,
    artifacts_yaml_path: Option<&str>, // Allow injection or fallback to embedded
) {
    let default_yaml = include_str!("../artifacts.yaml");
    let stmt = r#"
        INSERT INTO artifacts (
            evidence_id,
            file_id,
            partition_id,
            name,
            description,
            parser,
            tag,
            category
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    "#;

    let yaml_text = match artifacts_yaml_path {
        Some(path) => match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                let msg = format!("Failed to read artifacts YAML file at {}: {}", path, e);
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
        },
        None => default_yaml.to_string(),
    };

    let artifact_set: ArtifactSet = match ArtifactSet::from_yaml_str(&yaml_text) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("Failed to parse artifacts YAML: {}", e);
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
    };
    info!("Loaded {} artifact(s):", artifact_set.artifacts.len());

    // Make identify pass idempotent for this partition.
    if let Err(err) = sqlx::query(
        r#"
        DELETE FROM artifact_objects
        WHERE evidence_id = ?
          AND partition_id = ?;
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .execute(pool)
    .await
    {
        let msg = format!("Failed to clear existing parsed artefacts: {err}");
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

    if let Err(err) = sqlx::query(
        r#"
        DELETE FROM artifacts
        WHERE evidence_id = ?
          AND partition_id = ?;
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .execute(pool)
    .await
    {
        let msg = format!("Failed to clear existing artefacts: {err}");
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
            message: "Identifying known artefacts…".to_string(),
        },
    )
    .await;

    // Fetch all files once to avoid redundant queries in the loop
    let all_files_res = sqlx::query(
        "SELECT * FROM system_files \
             WHERE evidence_id = ?1 \
             AND partition_id = ?2;",
    )
    .bind(evidence_id)
    .bind(partition_id)
    .fetch_all(pool)
    .await;

    let all_files = match all_files_res {
        Ok(rows) => {
            let mut files = Vec::with_capacity(rows.len());
            for row in rows {
                match decode_system_file_row(&row) {
                    Ok(file) => files.push(file),
                    Err(e) => {
                        let msg = format!(
                            "Failed to decode system_files row for partition {}: {}",
                            partition_id, e
                        );
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
                }
            }
            files
        }
        Err(e) => {
            let msg = format!(
                "Failed to query DB for files in partition {}: {}",
                partition_id, e
            );
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
    };

    // Pre-compile all artifact regexes
    let mut compiled_artifacts = Vec::new();
    for artifact in &artifact_set.artifacts {
        let mut patterns = Vec::new();
        for path_spec in &artifact.paths {
            let pattern = path_spec.to_regex();
            match regex::Regex::new(&pattern) {
                Ok(rx) => patterns.push(rx),
                Err(e) => {
                    let msg = format!(
                        "Invalid regex pattern '{}' for artifact '{}': {e}",
                        pattern, artifact.name
                    );
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
            }
        }
        if !patterns.is_empty() {
            compiled_artifacts.push((artifact, patterns));
        }
    }

    // Now iterate over all files once and check against all artifacts
    for file in &all_files {
        for (artifact, regexes) in &compiled_artifacts {
            let mut matched = false;
            for rx in regexes {
                if rx.is_match(&file.absolute_path) {
                    matched = true;
                    break;
                }
            }

            if matched {
                info!(
                    "Artifact matched ({}): {}",
                    artifact.name, file.absolute_path
                );
                if let Err(err) = sqlx::query(stmt)
                    .bind(evidence_id)
                    .bind(file.id.unwrap_or(0) as i64)
                    .bind(partition_id)
                    .bind(&artifact.name)
                    .bind(&artifact.description)
                    .bind(&artifact.parser)
                    .bind(&artifact.tag)
                    .bind(format!("{:?}", &artifact.category))
                    .execute(pool)
                    .await
                {
                    let msg = format!("Artifact insertion error: {err:?}");
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
            }
        }
    }

    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Success,
            message: "Artefact identification complete.".to_string(),
        },
    )
    .await;
}

fn extract_artefact<F: Filesystem>(
    fs: &mut F,
    parser: &dyn ArtefactParser,
    fs_identifier: u64,
    absolute_path: &str,
) -> Result<Vec<ObjectParsed>>
where
    F::FileType: FileCommon,
{
    // Fetch FS record
    let record = match fs.get_file(fs_identifier) {
        Ok(r) => r,
        Err(_) => {
            // Fallback: try to get by path if ID lookup failed (e.g. empty FolderFS cache)
            fs.get_file_by_path(absolute_path, fs_identifier)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
        }
    };

    // Adapter: Read+Seek backed by Filesystem::read_file_slice
    let rs = FsFileReadSeek::new(fs, record);

    // Collect parsed objects
    let mut out: Vec<ObjectParsed> = Vec::new();
    let mut sink = |obj: ObjectParsed| -> Result<()> {
        out.push(obj);
        Ok(())
    };

    parser.run_into(ParserInput::ReadSeek(Box::new(rs)), &mut sink)?;
    Ok(out)
}

pub async fn extract_artefacts<F: Filesystem>(
    evidence_id: i64,
    partition_id: i64,
    pool: &SqlitePool,
    fs: &mut F,
    registry: &ParserRegistry,
    tx_progress: Option<Sender<IndexerEvent>>,
    cancel_token: Option<Arc<AtomicBool>>,
) where
    F::FileType: FileCommon,
{
    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Info,
            message: "Starting artefact extraction…".to_string(),
        },
    )
    .await;

    // Pull artefacts that specify a parser, joined to system_files to recover the FS identifier.
    let rows_res = sqlx::query(
        r#"
        SELECT
            a.id            AS artifact_id,
            a.file_id       AS file_id,
            a.parser        AS parser_name,
            sf.identifier   AS fs_identifier,
            sf.absolute_path AS absolute_path
        FROM artifacts a
        JOIN system_files sf
          ON sf.id = a.file_id
        WHERE a.evidence_id  = ?
          AND a.partition_id = ?
          AND a.parser IS NOT NULL
          AND TRIM(a.parser) <> ''
        ORDER BY a.id;
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .fetch_all(pool)
    .await;

    let rows = match rows_res {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("Failed to list artefacts to extract: {e:?}");
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
    };

    if rows.is_empty() {
        send_progress(
            &tx_progress,
            IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Success,
                message: "No artefacts with a parser to extract.".to_string(),
            },
        )
        .await;
        return;
    }

    let total = rows.len() as u64;

    // Write parsed objects in one transaction for this partition.
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            let msg = format!("Could not open DB transaction for extraction: {e:?}");
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
    };

    let mut processed_files = 0u64;
    let mut emitted_objects = 0u64;

    for row in rows {
        if let Some(token) = &cancel_token {
            if token.load(Ordering::Relaxed) {
                // Abort processing but keep what hasn't been reverted
                break;
            }
        }

        processed_files += 1;

        let artifact_id: i64 = row.get("artifact_id");
        let file_id: Option<i64> = row.get("file_id");
        let parser_name: String = row.get("parser_name");
        let parser_name = parser_name.trim();
        let fs_identifier_i64: i64 = row.get("fs_identifier");
        let abs_path: String = row.get("absolute_path");

        let parser_opt = registry.get(parser_name);

        let parser = match parser_opt {
            Some(p) => p,
            None => {
                let available_parsers: Vec<&str> = registry.keys().cloned().collect();
                let msg = format!(
                    "Artefact '{}' references unknown parser '{}' (file: {}). Available parsers: {:?}",
                    artifact_id, parser_name, abs_path, available_parsers
                );
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
                continue;
            }
        };

        let objs = match extract_artefact(fs, &**parser, fs_identifier_i64 as u64, &abs_path) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!(
                    "Extraction failed (parser={}, file={}): {e:?}",
                    parser_name, abs_path
                );
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
                continue;
            }
        };

        for obj in objs {
            emitted_objects += 1;

            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO artifact_objects (
                    evidence_id,
                    partition_id,
                    artifact_id,
                    file_id,
                    parser,
                    kind,
                    text,
                    json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                "#,
            )
            .bind(evidence_id)
            .bind(partition_id)
            .bind(artifact_id)
            .bind(file_id)
            .bind(obj.parser)
            .bind(obj.kind)
            .bind(obj.text)
            .bind(obj.json.to_string())
            .execute(&mut *tx)
            .await
            {
                let msg = format!("DB insert error for parsed object: {e:?}");
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
        }

        if processed_files % 50 == 0 || processed_files == total {
            send_progress(&tx_progress, IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Progress { current: processed_files, total },
                message: format!(
                    "Artefact extraction: {processed_files}/{total} files, {emitted_objects} objects emitted…"
                ),
            }).await;
        }
    }

    if let Err(e) = tx.commit().await {
        let msg = format!("Extraction commit error: {e:?}");
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
            message: format!(
            "Artefact extraction done: processed {total} files, emitted {emitted_objects} objects."
        ),
        },
    )
    .await;

    info!(
        "Artefact extraction done evidence_id={evidence_id} partition_id={partition_id}: \
         processed={total} emitted={emitted_objects}"
    );
}
