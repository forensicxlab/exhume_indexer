use super::spool::StagedRecord;
use super::*;
use exhume_artefacts::ObjectParsed;
use sqlx::{Sqlite, Transaction};
use std::io::{BufRead, BufReader};

pub async fn ensure_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let obsolete: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name IN ('signal_jobs','signal_attempts','signal_diagnostics'))",
    )
    .fetch_one(pool)
    .await?;
    if obsolete {
        return Err(sqlx::Error::Protocol(
            "unsupported development recovery schema; rebuild the derived index".into(),
        ));
    }
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='recovery_schema')",
    )
    .fetch_one(pool)
    .await?;
    if present {
        let version: Option<i64> =
            sqlx::query_scalar("SELECT version FROM recovery_schema WHERE id=1")
                .fetch_optional(pool)
                .await?;
        if version == Some(1) {
            return Ok(());
        }
        if version.is_some() {
            return Err(sqlx::Error::Protocol(
                "unsupported recovery schema version".into(),
            ));
        }
    }
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    for statement in r#"
    CREATE TABLE IF NOT EXISTS recovery_schema(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS recovery_jobs(evidence_id INTEGER NOT NULL,partition_id INTEGER NOT NULL,target_id TEXT PRIMARY KEY,artifact_id INTEGER NOT NULL,parser TEXT NOT NULL,status TEXT NOT NULL,details_json TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_recovery_jobs_scope ON recovery_jobs(evidence_id,partition_id,status);
    CREATE TABLE IF NOT EXISTS recovery_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT,evidence_id INTEGER NOT NULL,partition_id INTEGER NOT NULL,target_id TEXT NOT NULL,details_json TEXT NOT NULL,created_at INTEGER NOT NULL DEFAULT(strftime('%s','now')));
    CREATE INDEX IF NOT EXISTS idx_recovery_attempt_target ON recovery_attempts(target_id,id);
    CREATE TABLE IF NOT EXISTS recovery_diagnostics(id INTEGER PRIMARY KEY AUTOINCREMENT,attempt_id INTEGER NOT NULL,issue_json TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_recovery_diagnostics_attempt ON recovery_diagnostics(attempt_id,id);
"#.split(';').filter(|statement|!statement.trim().is_empty()) {
    sqlx::query(statement).execute(&mut *tx).await?;
}
    let version: Option<i64> = sqlx::query_scalar("SELECT version FROM recovery_schema WHERE id=1")
        .fetch_optional(&mut *tx)
        .await?;
    if version.is_none() {
        sqlx::query("INSERT INTO recovery_schema(id,version) VALUES(1,1)")
            .execute(&mut *tx)
            .await?;
    } else if version != Some(1) {
        return Err(sqlx::Error::Protocol(
            "unsupported recovery schema version".into(),
        ));
    }
    tx.commit().await?;
    Ok(())
}

pub(super) async fn inventory(pool: &SqlitePool, scope: RecoveryScope) -> Result<Option<i64>> {
    Ok(sqlx::query_scalar(
        "SELECT run_id FROM index_inventory WHERE evidence_id=? AND partition_id=?",
    )
    .bind(scope.evidence_id)
    .bind(scope.partition_id)
    .fetch_optional(pool)
    .await?)
}
pub(super) async fn previous(
    pool: &SqlitePool,
    scope: RecoveryScope,
    id: &str,
) -> Result<Option<RecoveryJob>> {
    let json: Option<String> = sqlx::query_scalar("SELECT details_json FROM recovery_jobs WHERE evidence_id=? AND partition_id=? AND target_id=?").bind(scope.evidence_id).bind(scope.partition_id).bind(id).fetch_optional(pool).await?;
    json.map(|s| serde_json::from_str(&s).map_err(Into::into))
        .transpose()
}
pub async fn load_recovery_jobs(pool: &SqlitePool, scope: RecoveryScope) -> Result<RecoveryReport> {
    ensure_schema(pool).await?;
    let rows: Vec<String> = sqlx::query_scalar("SELECT j.details_json FROM recovery_jobs j JOIN artifacts a ON a.id=j.artifact_id AND a.evidence_id=j.evidence_id AND a.partition_id=j.partition_id WHERE j.evidence_id=? AND j.partition_id=? ORDER BY j.artifact_id")
        .bind(scope.evidence_id).bind(scope.partition_id).fetch_all(pool).await?;
    Ok(RecoveryReport {
        jobs: rows
            .iter()
            .map(|json| serde_json::from_str(json))
            .collect::<std::result::Result<_, _>>()?,
    })
}
async fn guard_inventory(tx: &mut Transaction<'_, Sqlite>, job: &RecoveryJob) -> Result<()> {
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT run_id FROM index_inventory WHERE evidence_id=? AND partition_id=?",
    )
    .bind(job.scope.evidence_id)
    .bind(job.scope.partition_id)
    .fetch_optional(&mut **tx)
    .await?;
    ensure!(
        current == job.inventory_run_id,
        "Recovery inventory changed during recovery; discover the target again"
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM artifacts a JOIN system_files sf ON a.file_id=sf.id WHERE a.id=? AND a.evidence_id=? AND a.partition_id=? AND a.parser=? AND sf.absolute_path=? AND sf.id=?")
        .bind(job.artifact_id).bind(job.scope.evidence_id).bind(job.scope.partition_id).bind(&job.parser).bind(&job.primary_path).bind(job.sources.first().context("recovery primary source missing")?.system_file_id).fetch_one(&mut **tx).await?;
    ensure!(
        count == 1,
        "Recovery artefact identity changed during recovery"
    );
    Ok(())
}
async fn begin_attempt(tx: &mut Transaction<'_, Sqlite>, job: &mut RecoveryJob) -> Result<i64> {
    guard_inventory(tx, job).await?;
    // Another invocation may have published while this one prepared its input.
    // A failed attempt must retain that latest publication too.
    let current: Option<String> =
        sqlx::query_scalar("SELECT details_json FROM recovery_jobs WHERE target_id=?")
            .bind(&job.target_id)
            .fetch_optional(&mut **tx)
            .await?;
    if let Some(current) = current {
        job.published_attempt_id =
            serde_json::from_str::<RecoveryJob>(&current)?.published_attempt_id;
    }
    let result = sqlx::query("INSERT INTO recovery_attempts(evidence_id,partition_id,target_id,details_json) VALUES(?,?,?,'{}')")
        .bind(job.scope.evidence_id).bind(job.scope.partition_id).bind(&job.target_id).execute(&mut **tx).await?;
    let id = result.last_insert_rowid();
    job.attempt_id = Some(id);
    Ok(id)
}
async fn finish_attempt(
    tx: &mut Transaction<'_, Sqlite>,
    job: &RecoveryJob,
    id: i64,
) -> Result<()> {
    let json = serde_json::to_string(job)?;
    sqlx::query("UPDATE recovery_attempts SET details_json=? WHERE id=?")
        .bind(&json)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    upsert_job(tx, job).await
}
async fn upsert_job(tx: &mut Transaction<'_, Sqlite>, job: &RecoveryJob) -> Result<()> {
    let json = serde_json::to_string(job)?;
    let status = serde_json::to_value(job.status)?;
    sqlx::query("INSERT INTO recovery_jobs(evidence_id,partition_id,target_id,artifact_id,parser,status,details_json) VALUES(?,?,?,?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET artifact_id=excluded.artifact_id,parser=excluded.parser,status=excluded.status,details_json=excluded.details_json")
        .bind(job.scope.evidence_id).bind(job.scope.partition_id).bind(&job.target_id).bind(job.artifact_id).bind(&job.parser).bind(status.as_str().context("Recovery status must serialize as a string")?).bind(json).execute(&mut **tx).await?;
    Ok(())
}
pub(super) async fn register_jobs(pool: &SqlitePool, jobs: &mut [RecoveryJob]) -> Result<()> {
    if jobs.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for job in jobs {
        guard_inventory(&mut tx, job).await?;
        let current: Option<String> =
            sqlx::query_scalar("SELECT details_json FROM recovery_jobs WHERE target_id=?")
                .bind(&job.target_id)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(current) = current {
            job.published_attempt_id =
                serde_json::from_str::<RecoveryJob>(&current)?.published_attempt_id;
        }
        upsert_job(&mut tx, job).await?;
    }
    tx.commit().await?;
    Ok(())
}
pub(super) async fn save_attempt(pool: &SqlitePool, job: &mut RecoveryJob) -> Result<()> {
    let mut tx = pool.begin().await?;
    let id = begin_attempt(&mut tx, job).await?;
    finish_attempt(&mut tx, job, id).await?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn publish(
    pool: &SqlitePool,
    job: &mut RecoveryJob,
    parser: &'static str,
    records: std::fs::File,
    diagnostics: std::fs::File,
    cancel: Option<&AtomicBool>,
) -> Result<()> {
    check_cancel(cancel)?;
    let mut tx = pool.begin().await?;
    let attempt = begin_attempt(&mut tx, job).await?;
    sqlx::query("DELETE FROM artifact_attachment_refs WHERE artifact_object_id IN (SELECT id FROM artifact_objects WHERE evidence_id=? AND partition_id=? AND artifact_id=?)")
        .bind(job.scope.evidence_id).bind(job.scope.partition_id).bind(job.artifact_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM timeline_events WHERE artifact_object_id IN (SELECT id FROM artifact_objects WHERE evidence_id=? AND partition_id=? AND artifact_id=?)")
        .bind(job.scope.evidence_id).bind(job.scope.partition_id).bind(job.artifact_id).execute(&mut *tx).await?;
    sqlx::query(
        "DELETE FROM artifact_objects WHERE evidence_id=? AND partition_id=? AND artifact_id=?",
    )
    .bind(job.scope.evidence_id)
    .bind(job.scope.partition_id)
    .bind(job.artifact_id)
    .execute(&mut *tx)
    .await?;
    let mut lines = BufReader::new(records).lines();
    loop {
        let batch = lines
            .by_ref()
            .take(128)
            .map(|line| Ok(serde_json::from_str::<StagedRecord>(&line?)?))
            .collect::<Result<Vec<_>>>()?;
        if batch.is_empty() {
            break;
        }
        check_cancel(cancel)?;
        let objects: Vec<_> = batch
            .iter()
            .map(|r| ObjectParsed {
                parser,
                kind: if r.kind == "mobile.communication.attachment" {
                    "mobile.communication.attachment"
                } else {
                    "recovery.record"
                },
                text: String::new(),
                json: if r.kind == "mobile.communication.attachment" {
                    r.json.clone()
                } else {
                    serde_json::Value::Null
                },
            })
            .collect();
        let resolved = crate::artifacts::resolve_attachment_files_batch(
            &mut tx,
            job.scope.evidence_id,
            job.scope.partition_id,
            &objects,
        )
        .await?;
        for (record, resolved) in batch.into_iter().zip(resolved) {
            check_cancel(cancel)?;
            let result = sqlx::query("INSERT INTO artifact_objects(evidence_id,partition_id,artifact_id,file_id,parser,kind,text,json) VALUES(?,?,?,?,?,?,?,?)")
                .bind(job.scope.evidence_id).bind(job.scope.partition_id).bind(job.artifact_id).bind(job.sources.first().context("recovery primary source missing")?.system_file_id).bind(parser).bind(&record.kind).bind(record.text).bind(record.json.to_string()).execute(&mut *tx).await?;
            let object = result.last_insert_rowid();
            for event in record.timeline {
                sqlx::query("INSERT INTO timeline_events(evidence_id,partition_id,ts,source,event_type,description,file_id,artifact_object_id,actor) VALUES(?,?,?,?,?,?,?,?,?)")
                    .bind(job.scope.evidence_id).bind(job.scope.partition_id).bind(event.ts).bind(parser).bind(event.event_type).bind(event.description).bind(job.sources.first().context("recovery primary source missing")?.system_file_id).bind(object).bind(event.actor).execute(&mut *tx).await?;
            }
            if record.kind == "mobile.communication.attachment" {
                crate::artifacts::insert_attachment_ref(
                    &mut tx,
                    job.scope.evidence_id,
                    job.scope.partition_id,
                    object,
                    parser,
                    &record.json,
                    resolved.as_ref(),
                )
                .await?;
            }
        }
    }
    for line in BufReader::new(diagnostics).lines() {
        check_cancel(cancel)?;
        let issue: ParserIssue = serde_json::from_str(&line?)?;
        sqlx::query("INSERT INTO recovery_diagnostics(attempt_id,issue_json) VALUES(?,?)")
            .bind(attempt)
            .bind(serde_json::to_string(&issue)?)
            .execute(&mut *tx)
            .await?;
    }
    check_cancel(cancel)?;
    job.published_attempt_id = Some(attempt);
    finish_attempt(&mut tx, job, attempt).await?;
    tx.commit().await?;
    Ok(())
}

/// Emit final unresolved states and source-row diagnostics through the ordinary
/// reported-phase channel, after all prompting/retries and write transactions.
pub async fn report_recovery_outcomes(
    pool: &SqlitePool,
    report: &RecoveryReport,
    progress: Option<Sender<IndexerEvent>>,
) -> Result<()> {
    for job in &report.jobs {
        if !job.status.is_published() && job.status != RecoveryStatus::Cancelled {
            crate::send_progress(
                &progress,
                IndexerEvent {
                    evidence_id: job.scope.evidence_id,
                    event_type: IndexerEventType::Warning,
                    message: format!(
                        "{} target {}: {:?} ({})",
                        job.application, job.target_id, job.status, job.reason
                    ),
                },
            )
            .await;
        }
        if let Some(attempt) = job.attempt_id {
            let mut after = 0i64;
            loop {
                let rows = sqlx::query("SELECT id,issue_json FROM recovery_diagnostics WHERE attempt_id=? AND id>? ORDER BY id LIMIT 256").bind(attempt).bind(after).fetch_all(pool).await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    after = row.try_get("id")?;
                    let issue: ParserIssue = serde_json::from_str(row.try_get("issue_json")?)?;
                    crate::send_progress(
                        &progress,
                        IndexerEvent {
                            evidence_id: job.scope.evidence_id,
                            event_type: IndexerEventType::Warning,
                            message: format!(
                                "{} (parser {}, unit {:?})",
                                issue.message, job.parser, issue.unit
                            ),
                        },
                    )
                    .await;
                }
            }
        }
    }
    Ok(())
}

pub(crate) async fn current_issue_count(pool: &SqlitePool, scope: RecoveryScope) -> Result<u64> {
    let report = load_recovery_jobs(pool, scope).await?;
    let mut count = u64::try_from(report.unresolved_count())?;
    for job in report.jobs {
        if let Some(attempt) = job.published_attempt_id {
            let json: String =
                sqlx::query_scalar("SELECT details_json FROM recovery_attempts WHERE id=?")
                    .bind(attempt)
                    .fetch_one(pool)
                    .await?;
            let published: RecoveryJob = serde_json::from_str(&json)?;
            count = count
                .checked_add(published.issue_count)
                .context("Recovery issue count overflow")?;
        }
    }
    Ok(count)
}
