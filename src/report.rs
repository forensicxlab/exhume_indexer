//! Durable indexing runs and coverage diagnostics. Credentials are never stored.
use crate::{IndexerEvent, IndexerEventType};
use exhume_filesystem::{
    File, Filesystem, WalkEvent, WalkIssue, WalkOptions, WalkReport, WalkStatus,
};
use serde::{Deserialize, Serialize};
use sqlx::{SqliteConnection, SqlitePool};
use std::{
    error::Error,
    io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write},
    sync::{atomic::AtomicBool, Arc},
};
use tokio::sync::mpsc::Sender;
pub type IndexResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexPhase {
    FileSignature,
    ArtifactIdentification,
    ArtifactExtraction,
}
impl IndexPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileSignature => "file_signature",
            Self::ArtifactIdentification => "artifact_identification",
            Self::ArtifactExtraction => "artifact_extraction",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexIssueCode {
    FileRead,
    ParserFailed,
    ParserPartial,
    UnknownParser,
    InvalidConfiguration,
    Database,
    PhaseFailure,
}
#[derive(Serialize, Deserialize)]
struct PhaseDiagnostic {
    path: Option<String>,
    record_id: Option<u64>,
    code: IndexIssueCode,
    fatal: bool,
    message: String,
}

/// Collect typed phase failures separately from optional display progress.
/// Their metadata spool is replayed only after the phase releases its database
/// transaction, avoiding pool deadlocks and unbounded diagnostic accumulation.
pub async fn run_reported_phase<F, Fut>(
    pool: &SqlitePool,
    report: &mut IndexReport,
    phase: IndexPhase,
    progress: Option<Sender<IndexerEvent>>,
    cancel: Option<Arc<AtomicBool>>,
    operation: F,
) -> IndexResult<()>
where
    F: FnOnce(Sender<IndexerEvent>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    run_reported_phase_inner(pool, report, phase, progress, cancel, operation, false).await
}

/// Allow an operation to finish its cooperative cancellation and transaction
/// boundary before finalizing its durable phase report.
pub async fn run_reported_phase_cooperatively<F, Fut>(
    pool: &SqlitePool,
    report: &mut IndexReport,
    phase: IndexPhase,
    progress: Option<Sender<IndexerEvent>>,
    cancel: Option<Arc<AtomicBool>>,
    operation: F,
) -> IndexResult<()>
where
    F: FnOnce(Sender<IndexerEvent>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    run_reported_phase_inner(pool, report, phase, progress, cancel, operation, true).await
}

#[allow(clippy::too_many_arguments)]
async fn run_reported_phase_inner<F, Fut>(
    pool: &SqlitePool,
    report: &mut IndexReport,
    phase: IndexPhase,
    progress: Option<Sender<IndexerEvent>>,
    cancel: Option<Arc<AtomicBool>>,
    operation: F,
    cooperative: bool,
) -> IndexResult<()>
where
    F: FnOnce(Sender<IndexerEvent>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let result = run_phase_inner(
        pool,
        report,
        phase,
        progress,
        cancel,
        operation,
        cooperative,
    )
    .await
    .map_err(|error| error.to_string());
    if let Err(error) = &result {
        report.status = IndexStatus::Failed;
        let mut connection = pool.acquire().await?;
        save_report(&mut connection, report, Some(&error.to_string())).await?;
    }
    result.map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
async fn run_phase_inner<F, Fut>(
    pool: &SqlitePool,
    report: &mut IndexReport,
    phase: IndexPhase,
    progress: Option<Sender<IndexerEvent>>,
    cancel: Option<Arc<AtomicBool>>,
    operation: F,
    cooperative: bool,
) -> IndexResult<()>
where
    F: FnOnce(Sender<IndexerEvent>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if cancel
        .as_ref()
        .is_some_and(|token| token.load(std::sync::atomic::Ordering::Relaxed))
    {
        report.status = IndexStatus::Cancelled;
        let mut connection = pool.acquire().await?;
        save_report(&mut connection, report, None).await?;
        return Ok(());
    }
    let mut running = report.clone();
    running.status = IndexStatus::Running;
    {
        let mut connection = pool.acquire().await?;
        save_report(&mut connection, &running, None).await?;
    }
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<IndexerEvent>(128);
    let file = tempfile::tempfile()?;
    let collect = async move {
        let mut spool = BufWriter::new(file);
        let mut count = 0u64;
        let mut fatal = false;
        while let Some(event) = receiver.recv().await {
            let diagnostic = match &event.event_type {
                IndexerEventType::Issue {
                    code,
                    path,
                    record_id,
                    fatal,
                    ..
                } => Some(PhaseDiagnostic {
                    path: path.clone(),
                    record_id: *record_id,
                    code: *code,
                    fatal: *fatal,
                    message: event.message.clone(),
                }),
                IndexerEventType::Error => Some(PhaseDiagnostic {
                    path: None,
                    record_id: None,
                    code: IndexIssueCode::PhaseFailure,
                    fatal: false,
                    message: event.message.clone(),
                }),
                _ => None,
            };
            if let Some(diagnostic) = diagnostic {
                count += 1;
                fatal |= diagnostic.fatal;
                serde_json::to_writer(&mut spool, &diagnostic).map_err(std::io::Error::other)?;
                spool.write_all(b"\n")?;
            }
            if let Some(tx) = &progress {
                if !(count > 0 && matches!(event.event_type, IndexerEventType::Success)) {
                    let _ = tx.send(event).await;
                }
            }
        }
        spool.flush()?;
        let mut file = spool.into_inner().map_err(|e| e.into_error())?;
        file.seek(SeekFrom::Start(0))?;
        Ok::<_, std::io::Error>((file, count, fatal))
    };
    let execution = async {
        if cooperative {
            operation(sender).await;
            return;
        }
        let cancelled = async {
            if let Some(token) = &cancel {
                while !token.load(std::sync::atomic::Ordering::Relaxed) {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            _ = operation(sender) => {},
            _ = cancelled => {},
        }
    };
    let (_, result) = tokio::join!(execution, collect);
    let (file, count, fatal) = result?;
    report.phase_issues += count;
    report.recovery_issues = crate::recovery::current_issue_count(
        pool,
        crate::recovery::RecoveryScope {
            evidence_id: report.evidence_id,
            partition_id: report.partition_id,
        },
    )
    .await?;
    report.status = if fatal {
        IndexStatus::Failed
    } else if cancel
        .as_ref()
        .is_some_and(|token| token.load(std::sync::atomic::Ordering::Relaxed))
    {
        IndexStatus::Cancelled
    } else if report.issue_count() > 0 {
        IndexStatus::CompletedWithIssues
    } else {
        IndexStatus::Complete
    };
    let mut transaction = pool.begin().await?;
    for line in BufReader::new(file).lines() {
        let diagnostic: PhaseDiagnostic = serde_json::from_str(&line?)?;
        insert_issue(
            &mut transaction,
            report,
            phase.as_str(),
            diagnostic.path.as_deref(),
            diagnostic.record_id,
            serde_json::to_value(diagnostic.code)?.as_str().unwrap(),
            if diagnostic.fatal {
                "abort_phase"
            } else if diagnostic.code == IndexIssueCode::ParserPartial {
                "skip_parser_unit"
            } else {
                "skip_file"
            },
            &diagnostic.message,
            &serde_json::to_value(&diagnostic)?,
        )
        .await?;
    }
    save_report(
        &mut transaction,
        report,
        if fatal {
            Some("analysis phase failed; see index_issues")
        } else {
            None
        },
    )
    .await?;
    transaction.commit().await?;
    if fatal {
        return Err(format!(
            "{} failed; diagnostics stored in index run {}",
            phase.as_str(),
            report.run_id
        )
        .into());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexStatus {
    Running,
    Complete,
    CompletedWithIssues,
    Failed,
    Cancelled,
    Aborted,
}
impl IndexStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Complete => "complete",
            Self::CompletedWithIssues => "completed_with_issues",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Aborted => "aborted",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexReport {
    pub run_id: i64,
    pub evidence_id: i64,
    pub partition_id: i64,
    pub status: IndexStatus,
    pub indexed_paths: u64,
    pub walk: WalkReport,
    pub phase_issues: u64,
    /// Current unresolved Signal jobs and diagnostics on published attempts.
    /// Historical failed credential attempts do not keep a resolved job incomplete.
    #[serde(default)]
    pub recovery_issues: u64,
}
impl IndexReport {
    pub fn issue_count(&self) -> u64 {
        self.walk
            .issues
            .saturating_add(self.phase_issues)
            .saturating_add(self.recovery_issues)
    }
    pub fn summary(&self) -> String {
        format!("Index {}: {} paths indexed; {} entry gaps, {} unreadable subtrees, {} skipped index blocks, {} analysis issues (run {}).",
            self.status.as_str(),self.indexed_paths,self.walk.skipped_entries,self.walk.unreadable_subtrees,self.walk.skipped_index_blocks,self.phase_issues.saturating_add(self.recovery_issues),self.run_id)
    }
}
#[derive(Serialize, Deserialize)]
enum SpoolEntry {
    File(Box<File>),
    Issue(WalkIssue),
}

pub(crate) async fn ensure_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS index_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL, partition_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            started_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            finished_at INTEGER, report_json TEXT NOT NULL DEFAULT '{}',
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_index_runs_partition ON index_runs(evidence_id,partition_id,id);
        CREATE TABLE IF NOT EXISTS index_issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL,
            evidence_id INTEGER NOT NULL, partition_id INTEGER NOT NULL,
            phase TEXT NOT NULL, path TEXT, record_id INTEGER,
            code TEXT NOT NULL, action TEXT NOT NULL, message TEXT NOT NULL,
            details_json TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_index_issues_run ON index_issues(run_id,id);
        CREATE TABLE IF NOT EXISTS index_inventory (
            evidence_id INTEGER NOT NULL, partition_id INTEGER NOT NULL, run_id INTEGER NOT NULL,
            PRIMARY KEY (evidence_id,partition_id)
        );
        CREATE INDEX IF NOT EXISTS idx_sysfiles_ev_part_identifier ON system_files(evidence_id,partition_id,identifier);
        CREATE INDEX IF NOT EXISTS idx_files_ev_path ON system_files(evidence_id,absolute_path);
    "#).execute(pool).await?;
    Ok(())
}
pub async fn latest_inventory_report(
    pool: &SqlitePool,
    evidence: i64,
    partition: i64,
) -> IndexResult<Option<IndexReport>> {
    crate::recovery::ensure_schema(pool).await?;
    let value=sqlx::query_scalar::<_,String>("SELECT r.report_json FROM index_inventory i JOIN index_runs r ON r.id=i.run_id WHERE i.evidence_id=? AND i.partition_id=?")
        .bind(evidence).bind(partition).fetch_optional(pool).await?;
    value
        .map(|v| serde_json::from_str(&v).map_err(Into::into))
        .transpose()
}
pub async fn load_index_report(pool: &SqlitePool, run: i64) -> IndexResult<IndexReport> {
    crate::recovery::ensure_schema(pool).await?;
    let json = sqlx::query_scalar::<_, String>("SELECT report_json FROM index_runs WHERE id=?")
        .bind(run)
        .fetch_one(pool)
        .await?;
    Ok(serde_json::from_str(&json)?)
}
pub(crate) async fn save_report(
    connection: &mut SqliteConnection,
    report: &IndexReport,
    error: Option<&str>,
) -> IndexResult<()> {
    sqlx::query("UPDATE index_runs SET status=?,finished_at=CASE WHEN ?='running' THEN NULL ELSE strftime('%s','now') END,report_json=?,error=? WHERE id=?")
        .bind(report.status.as_str()).bind(report.status.as_str()).bind(serde_json::to_string(report)?).bind(error).bind(report.run_id)
        .execute(connection).await?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_issue(
    connection: &mut SqliteConnection,
    report: &IndexReport,
    phase: &str,
    path: Option<&str>,
    record: Option<u64>,
    code: &str,
    action: &str,
    message: &str,
    details: &serde_json::Value,
) -> IndexResult<()> {
    sqlx::query("INSERT INTO index_issues(run_id,evidence_id,partition_id,phase,path,record_id,code,action,message,details_json) VALUES(?,?,?,?,?,?,?,?,?,?)")
        .bind(report.run_id).bind(report.evidence_id).bind(report.partition_id).bind(phase).bind(path).bind(record.map(|v|v as i64))
        .bind(code).bind(action).bind(message).bind(serde_json::to_string(details)?).execute(connection).await?;
    Ok(())
}
async fn persist_walk_issue(
    connection: &mut SqliteConnection,
    report: &IndexReport,
    issue: &WalkIssue,
) -> IndexResult<()> {
    insert_issue(
        connection,
        report,
        "discovery",
        Some(&issue.path),
        issue.record_id,
        serde_json::to_value(issue.code)?.as_str().unwrap(),
        serde_json::to_value(issue.action)?.as_str().unwrap(),
        &issue.message,
        &serde_json::to_value(issue)?,
    )
    .await
}
async fn persist_spooled_issues(
    file: std::fs::File,
    pool: &SqlitePool,
    report: &IndexReport,
    error: Option<&str>,
) -> IndexResult<()> {
    let mut transaction = pool.begin().await?;
    for line in BufReader::new(file).lines() {
        if let SpoolEntry::Issue(issue) = serde_json::from_str::<SpoolEntry>(&line?)? {
            persist_walk_issue(&mut transaction, report, &issue).await?;
        }
    }
    save_report(&mut transaction, report, error).await?;
    transaction.commit().await?;
    Ok(())
}

/// A metadata-only spool bounds discovery memory without requiring filesystem
/// implementations to be Send or holding a database transaction during reads.
pub async fn index_filesystem_with_report<F: Filesystem>(
    fs: &mut F,
    evidence: i64,
    partition: i64,
    pool: &SqlitePool,
    progress: Option<Sender<IndexerEvent>>,
    cancel: Option<Arc<AtomicBool>>,
    path_prefix: Option<&str>,
) -> IndexResult<IndexReport> {
    ensure_schema(pool).await?;
    let previous = sqlx::query_scalar::<_, i64>(
        "SELECT run_id FROM index_inventory WHERE evidence_id=? AND partition_id=?",
    )
    .bind(evidence)
    .bind(partition)
    .fetch_optional(pool)
    .await?;
    let run = sqlx::query(
        "INSERT INTO index_runs(evidence_id,partition_id,status) VALUES(?,?,'running')",
    )
    .bind(evidence)
    .bind(partition)
    .execute(pool)
    .await?
    .last_insert_rowid();
    let mut report = IndexReport {
        run_id: run,
        evidence_id: evidence,
        partition_id: partition,
        status: IndexStatus::Running,
        indexed_paths: 0,
        walk: WalkReport::default(),
        phase_issues: 0,
        recovery_issues: 0,
    };
    {
        let mut connection = pool.acquire().await?;
        save_report(&mut connection, &report, None).await?;
    }
    let result = discover_and_ingest(
        fs,
        &mut report,
        pool,
        previous,
        progress,
        cancel,
        path_prefix,
    )
    .await
    .map_err(|error| error.to_string());
    if let Err(error) = result {
        report.status = IndexStatus::Failed;
        report.indexed_paths = 0;
        let mut connection = pool.acquire().await?;
        save_report(&mut connection, &report, Some(&error.to_string())).await?;
        return Err(error.into());
    }
    Ok(report)
}

async fn discover_and_ingest<F: Filesystem>(
    fs: &mut F,
    report: &mut IndexReport,
    pool: &SqlitePool,
    previous: Option<i64>,
    progress: Option<Sender<IndexerEvent>>,
    cancel: Option<Arc<AtomicBool>>,
    path_prefix: Option<&str>,
) -> IndexResult<()> {
    let evidence = report.evidence_id;
    let mut spool = BufWriter::new(tempfile::tempfile()?);
    let options = WalkOptions {
        cancel_token: cancel.clone(),
        ..WalkOptions::default()
    };
    let mut count = 0u64;
    let result = fs
        .walk_fs(&options, &mut |item| {
            match item {
                WalkEvent::File(file) => {
                    count += 1;
                    serde_json::to_writer(&mut spool, &SpoolEntry::File(Box::new(file)))?;
                    spool.write_all(b"\n")?;
                    if count.is_multiple_of(500) || count <= 20 {
                        if let Some(tx) = &progress {
                            let _ = tx.try_send(IndexerEvent {
                                evidence_id: evidence,
                                event_type: IndexerEventType::Progress {
                                    current: count,
                                    total: 0,
                                },
                                message: format!("Discovering files: {count} validated paths."),
                            });
                        }
                    }
                }
                WalkEvent::Issue(issue) => {
                    if let Some(tx) = &progress {
                        let _ = tx.try_send(IndexerEvent {
                            evidence_id: evidence,
                            event_type: IndexerEventType::WalkIssue(issue.clone()),
                            message: format!("{}: {}", issue.path, issue.message),
                        });
                    }
                    serde_json::to_writer(&mut spool, &SpoolEntry::Issue(issue))?;
                    spool.write_all(b"\n")?;
                }
                WalkEvent::Status(message) => {
                    if let Some(tx) = &progress {
                        let _ = tx.try_send(IndexerEvent {
                            evidence_id: evidence,
                            event_type: IndexerEventType::Info,
                            message,
                        });
                    }
                }
            }
            Ok(())
        })
        .map_err(|error| {
            let message = error.to_string();
            (error.report, message)
        });
    let failure = match result {
        Ok(walk) => {
            report.walk = walk;
            None
        }
        Err((walk, error)) => {
            report.walk = walk;
            report.status = IndexStatus::Failed;
            Some(error)
        }
    };
    // Preserve observed coverage even if flushing a failed callback's spool
    // also fails (for example, a full temporary-filesystem volume).
    spool.flush()?;
    let mut file = spool.into_inner().map_err(|e| e.into_error())?;
    file.seek(SeekFrom::Start(0))?;
    if let Some(error) = failure {
        persist_spooled_issues(file, pool, report, Some(&error)).await?;
        return Err(error.into());
    }
    report.status = match report.walk.status {
        WalkStatus::Complete => IndexStatus::Complete,
        WalkStatus::CompletedWithIssues => IndexStatus::CompletedWithIssues,
        WalkStatus::Cancelled => IndexStatus::Cancelled,
        WalkStatus::Aborted => IndexStatus::Aborted,
        WalkStatus::Failed => IndexStatus::Failed,
    };
    if matches!(report.status, IndexStatus::Cancelled | IndexStatus::Aborted) {
        persist_spooled_issues(file, pool, report, None).await?;
        announce(&progress, report).await;
        return Ok(());
    }
    // Diagnostics survive an inventory transaction rollback. Both handles share
    // a seek cursor, so reset it before the second sequential pass.
    let mut pending = report.clone();
    pending.status = IndexStatus::Running;
    persist_spooled_issues(file.try_clone()?, pool, &pending, None).await?;
    file.seek(SeekFrom::Start(0))?;
    let result = ingest(
        file,
        report,
        pool,
        previous,
        cancel,
        path_prefix,
        progress.clone(),
    )
    .await
    .map_err(|error| {
        let interrupted = error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::Interrupted);
        (interrupted, error.to_string())
    });
    if let Err((interrupted, error)) = result {
        report.indexed_paths = 0;
        report.status = if interrupted {
            IndexStatus::Cancelled
        } else {
            IndexStatus::Failed
        };
        let mut connection = pool.acquire().await?;
        save_report(&mut connection, report, Some(&error.to_string())).await?;
        if report.status == IndexStatus::Cancelled {
            return Ok(());
        }
        return Err(error.into());
    }
    announce(&progress, report).await;
    Ok(())
}
pub async fn announce(progress: &Option<Sender<IndexerEvent>>, report: &IndexReport) {
    crate::send_progress(
        progress,
        IndexerEvent {
            evidence_id: report.evidence_id,
            event_type: if report.status == IndexStatus::Complete {
                IndexerEventType::Success
            } else {
                IndexerEventType::Warning
            },
            message: report.summary(),
        },
    )
    .await;
}
async fn ingest(
    file: std::fs::File,
    report: &mut IndexReport,
    pool: &SqlitePool,
    previous: Option<i64>,
    cancel: Option<Arc<AtomicBool>>,
    path_prefix: Option<&str>,
    progress: Option<Sender<IndexerEvent>>,
) -> IndexResult<()> {
    let mut tx = pool.begin().await?;
    let current = sqlx::query_scalar::<_, i64>(
        "SELECT run_id FROM index_inventory WHERE evidence_id=? AND partition_id=?",
    )
    .bind(report.evidence_id)
    .bind(report.partition_id)
    .fetch_optional(&mut *tx)
    .await?;
    if current != previous {
        return Err(
            "another index run published this partition during discovery; retry indexing".into(),
        );
    }
    let existing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM system_files WHERE evidence_id=? AND partition_id=?",
    )
    .bind(report.evidence_id)
    .bind(report.partition_id)
    .fetch_one(&mut *tx)
    .await?;
    let seen = format!("index_seen_{}", report.run_id);
    if existing > 0 {
        sqlx::query(&format!("CREATE TEMP TABLE {seen}(id INTEGER PRIMARY KEY)"))
            .execute(&mut *tx)
            .await?;
    }
    // These are derived results tied to the replaced inventory; user annotations
    // live outside these tables and matching file identities keep their IDs.
    for table in [
        "recovery_jobs",
        "artifact_attachment_refs",
        "timeline_events",
        "artifact_objects",
        "artifacts",
    ] {
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE evidence_id=? AND partition_id=?"
        ))
        .bind(report.evidence_id)
        .bind(report.partition_id)
        .execute(&mut *tx)
        .await?;
    }
    for line in BufReader::new(file).lines() {
        if cancel
            .as_ref()
            .is_some_and(|token| token.load(std::sync::atomic::Ordering::Relaxed))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "index ingestion cancelled before commit",
            )
            .into());
        }
        match serde_json::from_str::<SpoolEntry>(&line?)? {
            SpoolEntry::Issue(_) => {}
            SpoolEntry::File(file) => {
                let key = crate::normalize_path_key(&file.absolute_path);
                let generation = file
                    .metadata
                    .pointer("/header/sequence_number")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let id = if existing > 0 {
                    sqlx::query_scalar::<_,i64>("SELECT id FROM system_files WHERE evidence_id=? AND partition_id=? AND path_key=? AND identifier=? AND COALESCE(json_extract(metadata,'$.header.sequence_number'),0)=? ORDER BY id LIMIT 1")
                        .bind(report.evidence_id).bind(report.partition_id).bind(&key).bind(file.identifier as i64).bind(generation as i64)
                        .fetch_optional(&mut *tx).await?
                } else {
                    None
                };
                let statement = if id.is_some() {
                    "UPDATE system_files SET evidence_id=?,partition_id=?,identifier=?,absolute_path=?,name=?,ftype=?,size=?,created=?,modified=?,accessed=?,permissions=?,owner=?,\"group\"=?,display=?,path_key=?,parent_path_key=?,depth=?,is_dir=?,sig_name=?,sig_mime=?,sig_exts=?,anomaly_flag=NULL,host_path=?,metadata=? WHERE id=?"
                } else {
                    "INSERT INTO system_files(evidence_id,partition_id,identifier,absolute_path,name,ftype,size,created,modified,accessed,permissions,owner,\"group\",display,path_key,parent_path_key,depth,is_dir,sig_name,sig_mime,sig_exts,host_path,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                };
                let host = path_prefix.map(|prefix| {
                    format!(
                        "{}{}",
                        prefix.trim_end_matches('/'),
                        if file.absolute_path == "/" {
                            ""
                        } else {
                            &file.absolute_path
                        }
                    )
                });
                let query = sqlx::query(statement)
                    .bind(report.evidence_id)
                    .bind(report.partition_id)
                    .bind(file.identifier as i64)
                    .bind(&file.absolute_path)
                    .bind(&file.name)
                    .bind(&file.ftype)
                    .bind(file.size as i64)
                    .bind(file.created.map(|v| v as i64))
                    .bind(file.modified.map(|v| v as i64))
                    .bind(file.accessed.map(|v| v as i64))
                    .bind(&file.permissions)
                    .bind(&file.owner)
                    .bind(&file.group)
                    .bind(&file.display)
                    .bind(&key)
                    .bind(crate::compute_parent_path_key(&key))
                    .bind(crate::compute_depth(&key))
                    .bind(i64::from(crate::is_directory_type(&file.ftype)))
                    .bind(Option::<String>::None)
                    .bind(Option::<String>::None)
                    .bind(Option::<String>::None)
                    .bind(host)
                    .bind(sqlx::types::Json(&file.metadata));
                let result = if let Some(id) = id {
                    query.bind(id).execute(&mut *tx).await?
                } else {
                    query.execute(&mut *tx).await?
                };
                let id = id.unwrap_or_else(|| result.last_insert_rowid());
                if existing > 0 {
                    sqlx::query(&format!("INSERT OR IGNORE INTO {seen}(id) VALUES(?)"))
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                }
                report.indexed_paths += 1;
                if report.indexed_paths.is_multiple_of(1000) {
                    if let Some(tx) = &progress {
                        let _ = tx.try_send(IndexerEvent {
                            evidence_id: report.evidence_id,
                            event_type: IndexerEventType::Progress {
                                current: report.indexed_paths,
                                total: report.walk.discovered(),
                            },
                            message: format!(
                                "Indexed {}/{} paths.",
                                report.indexed_paths,
                                report.walk.discovered()
                            ),
                        });
                    }
                }
            }
        }
    }
    if existing > 0 {
        sqlx::query(&format!("DELETE FROM system_files WHERE evidence_id=? AND partition_id=? AND id NOT IN (SELECT id FROM {seen})"))
            .bind(report.evidence_id).bind(report.partition_id).execute(&mut *tx).await?;
        sqlx::query(&format!("DROP TABLE {seen}"))
            .execute(&mut *tx)
            .await?;
    }
    if cancel
        .as_ref()
        .is_some_and(|token| token.load(std::sync::atomic::Ordering::Relaxed))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "index ingestion cancelled before commit",
        )
        .into());
    }
    save_report(&mut tx, report, None).await?;
    sqlx::query("INSERT INTO index_inventory(evidence_id,partition_id,run_id) VALUES(?,?,?) ON CONFLICT(evidence_id,partition_id) DO UPDATE SET run_id=excluded.run_id")
        .bind(report.evidence_id).bind(report.partition_id).bind(report.run_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
