use exhume_filesystem::filesystem::{DirectoryCommon, FileCommon, FileKind};
use exhume_filesystem::Filesystem;
use file_type::FileType;
use sqlx::{Pool, Row, Sqlite};
use tokio::sync::mpsc::Sender;
use tracing::{error, info};

use crate::{send_progress, IndexerEvent, IndexerEventType};

const SAMPLE_LEN: usize = 8192; // 8 KiB of magic bytes

pub async fn identify_file_types<T: Filesystem>(
    fs: &mut T,
    evidence_id: i64,
    partition_id: i64,
    pool: &Pool<Sqlite>,
    tx_progress: Option<Sender<IndexerEvent>>,
) where
    T::DirectoryType: DirectoryCommon,
{
    identify_file_types_with_cancellation(fs, evidence_id, partition_id, pool, tx_progress, None)
        .await;
}

/// Identify regular-file content while allowing a caller to stop at record boundaries.
pub async fn identify_file_types_with_cancellation<T: Filesystem>(
    fs: &mut T,
    evidence_id: i64,
    partition_id: i64,
    pool: &Pool<Sqlite>,
    tx_progress: Option<Sender<IndexerEvent>>,
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) where
    T::DirectoryType: DirectoryCommon,
{
    info!("Starting file-signature identification…");

    //--------------------------------------------------------------
    // 1) Pull identifiers of every regular, non-empty file.
    //--------------------------------------------------------------
    let rows_err = match sqlx::query(
        r#"
        SELECT identifier, absolute_path
        FROM   system_files
        WHERE  evidence_id  = ?
          AND  partition_id = ?
          AND  size        > 0
          AND  lower(ftype) NOT IN ('directory', 'dir', 'symlink', 'symbolic link', 'special')
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .fetch_all(pool)
    .await
    {
        Ok(r) => Ok(r),
        Err(e) => Err(format!("Could not list files for signature pass: {e:?}")),
    };

    let rows = match rows_err {
        Ok(r) => r,
        Err(msg) => {
            send_progress(
                &tx_progress,
                IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Issue {
                        phase: crate::report::IndexPhase::FileSignature,
                        code: crate::report::IndexIssueCode::Database,
                        path: None,
                        record_id: None,
                        fatal: true,
                    },
                    message: msg.clone(),
                },
            )
            .await;
            error!("{}", msg);
            return;
        }
    };

    let total = rows.len() as u64;
    if total == 0 {
        send_progress(
            &tx_progress,
            IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Success,
                message: "No regular file to analyse (skipping file-type module).".to_string(),
            },
        )
        .await;
        return;
    }

    //--------------------------------------------------------------
    // 2) Bulk update in a single transaction.
    //--------------------------------------------------------------
    let tx_res = match pool.begin().await {
        Ok(t) => Ok(t),
        Err(e) => Err(format!("Could not open DB transaction: {e:?}")),
    };

    let mut tx = match tx_res {
        Ok(t) => t,
        Err(msg) => {
            send_progress(
                &tx_progress,
                IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Issue {
                        phase: crate::report::IndexPhase::FileSignature,
                        code: crate::report::IndexIssueCode::Database,
                        path: None,
                        record_id: None,
                        fatal: true,
                    },
                    message: msg.clone(),
                },
            )
            .await;
            error!("{}", msg);
            return;
        }
    };

    //--------------------------------------------------------------
    // 3) For every file: read prefix → detect → UPDATE … .bind().
    //--------------------------------------------------------------
    let mut processed = 0u64;

    for row in rows {
        if cancel
            .as_ref()
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        {
            return;
        }
        let record_id = row.get::<i64, _>("identifier") as u64;
        let path = row.get::<String, _>("absolute_path");

        // FS record - Try ID first, then fallback to path for FolderFS
        let record = match fs.get_file(record_id).map_err(|error| error.to_string()) {
            Ok(rec) => rec,
            Err(_) => match fs
                .get_file_by_path(&path, record_id)
                .map_err(|error| error.to_string())
            {
                Ok(rec) => rec,
                Err(e) => {
                    let message = format!("get_file error id={record_id} path={path}: {e}");
                    error!("{message}");
                    signature_issue(&tx_progress, evidence_id, record_id, &path, message, false)
                        .await;
                    continue;
                }
            },
        };

        if record.entry_kind() != FileKind::Regular {
            continue;
        }

        // Efficient prefix read
        let prefix_result = fs.read_file_prefix(&record, SAMPLE_LEN).map_err(|error| {
            let unsupported = error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::Unsupported)
                || matches!(
                    error.downcast_ref::<exhume_filesystem::decmpfs::DecmpfsError>(),
                    Some(exhume_filesystem::decmpfs::DecmpfsError::UnsupportedCompressionType(_))
                );
            (error.to_string(), unsupported)
        });
        let prefix = match prefix_result {
            Ok(bytes) => bytes,
            Err((detail, unsupported)) => {
                let message = format!("read_file_prefix error id={record_id}: {detail}");
                error!("{message}");
                send_progress(
                    &tx_progress,
                    IndexerEvent {
                        evidence_id,
                        event_type: IndexerEventType::Issue {
                            phase: crate::report::IndexPhase::FileSignature,
                            code: if unsupported {
                                crate::report::IndexIssueCode::UnsupportedContent
                            } else {
                                crate::report::IndexIssueCode::FileRead
                            },
                            path: Some(path.clone()),
                            record_id: Some(record_id),
                            fatal: false,
                        },
                        message,
                    },
                )
                .await;
                continue;
            }
        };

        // Signature → UPDATE
        let ft = FileType::from_bytes(&prefix);

        // Detect extension mismatch: file's actual extension not in signature's known extensions
        let sig_exts = ft.extensions();
        let file_ext = std::path::Path::new(&path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let anomaly_flag: Option<i64> = if !sig_exts.is_empty() && !file_ext.is_empty() {
            let known: Vec<String> = sig_exts.iter().map(|e| e.to_lowercase()).collect();
            if known.contains(&file_ext) {
                None
            } else {
                Some(1)
            }
        } else {
            None
        };

        let update_err = match sqlx::query(
            r#"
            UPDATE system_files
               SET sig_name     = ?,
                   sig_mime     = ?,
                   sig_exts     = ?,
                   anomaly_flag = ?
             WHERE evidence_id  = ?
               AND partition_id = ?
               AND identifier   = ?
            "#,
        )
        .bind(ft.name())
        .bind(ft.media_types().join(","))
        .bind(sig_exts.join(","))
        .bind(anomaly_flag)
        .bind(evidence_id)
        .bind(partition_id)
        .bind(record_id as i64)
        .execute(&mut *tx)
        .await
        {
            Ok(_) => None,
            Err(e) => Some(format!("DB update error id={record_id}: {e:?}")),
        };

        if let Some(msg) = update_err {
            error!("{}", msg);
            signature_issue(&tx_progress, evidence_id, record_id, &path, msg, true).await;
            return;
        }

        processed += 1;
        if processed.is_multiple_of(500) || processed == total {
            send_progress(
                &tx_progress,
                IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Progress {
                        current: processed,
                        total,
                    },
                    message: format!("Signature analysed for {processed}/{total} files…"),
                },
            )
            .await;
        }
    }

    //--------------------------------------------------------------
    // 4) Commit.
    //--------------------------------------------------------------
    let commit_err = match tx.commit().await {
        Ok(_) => None,
        Err(e) => Some(format!("Signature-pass commit error: {e:?}")),
    };

    if let Some(msg) = commit_err {
        send_progress(
            &tx_progress,
            IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Issue {
                    phase: crate::report::IndexPhase::FileSignature,
                    code: crate::report::IndexIssueCode::Database,
                    path: None,
                    record_id: None,
                    fatal: true,
                },
                message: msg.clone(),
            },
        )
        .await;
        error!("{}", msg);
        return;
    }

    info!(
        "File-signature identification completed for evidence {} partition {}.",
        evidence_id, partition_id
    );

    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Success,
            message: format!("File-signature identification done for {total} files."),
        },
    )
    .await;
}

async fn signature_issue(
    progress: &Option<Sender<IndexerEvent>>,
    evidence_id: i64,
    record_id: u64,
    path: &str,
    message: String,
    fatal: bool,
) {
    send_progress(
        progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Issue {
                phase: crate::report::IndexPhase::FileSignature,
                code: if fatal {
                    crate::report::IndexIssueCode::Database
                } else {
                    crate::report::IndexIssueCode::FileRead
                },
                path: Some(path.to_owned()),
                record_id: Some(record_id),
                fatal,
            },
            message,
        },
    )
    .await;
}
