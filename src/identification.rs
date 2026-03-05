use exhume_filesystem::filesystem::{DirectoryCommon, FileCommon};
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
          AND  ftype       != 'Directory'
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .fetch_all(pool)
    .await {
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
                    event_type: IndexerEventType::Error,
                    message: msg.clone(),
                },
            ).await;
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
        ).await;
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
                    event_type: IndexerEventType::Error,
                    message: msg.clone(),
                },
            ).await;
            error!("{}", msg);
            return;
        }
    };

    //--------------------------------------------------------------
    // 3) For every file: read prefix → detect → UPDATE … .bind().
    //--------------------------------------------------------------
    let mut processed = 0u64;

    for row in rows {
        let record_id = row.get::<i64, _>("identifier") as u64;
        let path = row.get::<String, _>("absolute_path");

        // FS record - Try ID first, then fallback to path for FolderFS
        let record = match fs.get_file(record_id) {
            Ok(rec) => rec,
            Err(_) => {
                match fs.get_file_by_path(&path, record_id) {
                    Ok(rec) => rec,
                    Err(e) => {
                        error!("get_file error id={record_id} path={path}: {e}");
                        continue;
                    }
                }
            }
        };

        if record.is_dir() {
            continue;
        }

        // Efficient prefix read
        let prefix = match fs.read_file_prefix(&record, SAMPLE_LEN) {
            Ok(v) => v,
            Err(e) => {
                error!("read_file_prefix error id={record_id}: {e}");
                continue;
            }
        };

        // Signature → UPDATE
        let ft = FileType::from_bytes(&prefix);
        
        let update_err = match sqlx::query(
            r#"
            UPDATE system_files
               SET sig_name = ?,
                   sig_mime = ?,
                   sig_exts = ?
             WHERE evidence_id  = ?
               AND partition_id = ?
               AND identifier   = ?
            "#,
        )
        .bind(ft.name())
        .bind(ft.media_types().join(","))
        .bind(ft.extensions().join(","))
        .bind(evidence_id)
        .bind(partition_id)
        .bind(record_id as i64)
        .execute(&mut *tx)
        .await {
            Ok(_) => None,
            Err(e) => Some(format!("DB update error id={record_id}: {e:?}")),
        };

        if let Some(msg) = update_err {
            error!("{}", msg);
        }

        processed += 1;
        if processed % 500 == 0 || processed == total {
            send_progress(
                &tx_progress,
                IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Info,
                    message: format!("Signature analysed for {processed}/{total} files…"),
                },
            ).await;
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
                event_type: IndexerEventType::Error,
                message: msg.clone(),
            },
        ).await;
        error!("{}", msg);
        return;
    }

    info!("File-signature identification completed for evidence {} partition {}.", evidence_id, partition_id);

    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Success,
            message: format!("File-signature identification done for {total} files."),
        },
    ).await;
}
