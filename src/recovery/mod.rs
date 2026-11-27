//! Evidence-scoped preparation, pending inputs, retries and atomic publication.
//! Application rules live in `apps`; shared format decoders live in artefacts.
pub mod apps;
pub(crate) mod evidence;
mod execution;
mod persistence;
mod preparation;
mod providers;
mod reported;
mod session;
mod spool;
mod types;
pub use reported::run_reported_recovery;
#[cfg(test)]
mod tests;
pub(crate) use persistence::current_issue_count;
pub use persistence::{ensure_schema, load_recovery_jobs, report_recovery_outcomes};
pub use preparation::*;
pub use session::RecoverySession;
pub use types::*;

use crate::{IndexerEvent, IndexerEventType, ParserProgressPhase};
use anyhow::{ensure, Context, Result};
use exhume_artefacts::{
    parsers::ParserRegistry, run_parser_with_options, ParserInput, ParserIssue, ParserOptions,
    ParserSecret,
};
use exhume_filesystem::{filesystem::FileCommon, Filesystem};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::mpsc::Sender;

#[derive(Debug)]
pub struct PreparationFailure {
    pub status: RecoveryStatus,
    pub reason: &'static str,
}
impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason)
    }
}
impl std::error::Error for PreparationFailure {}
fn blocked(status: RecoveryStatus, reason: &'static str) -> anyhow::Error {
    PreparationFailure { status, reason }.into()
}
pub(crate) fn check_cancel(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
        Err(blocked(RecoveryStatus::Cancelled, "cancelled"))
    } else {
        Ok(())
    }
}
// Borrowed Filesystem adapters cannot be moved into a 'static worker. On a
// multithread Tokio runtime, release the executor worker during bounded native
// I/O/crypto/parsing. Current-thread callers retain the existing serial contract.
pub(crate) fn blocking<T>(operation: impl FnOnce() -> T) -> T {
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}
pub(crate) fn scoped_id(
    prefix: &str,
    scope: RecoveryScope,
    inventory: Option<i64>,
    path: &str,
) -> String {
    let mut hash = Sha256::new();
    hash.update(format!(
        "{}:{}:{inventory:?}:",
        scope.evidence_id, scope.partition_id
    ));
    hash.update(path.as_bytes());
    format!("{prefix}{}", hex::encode(hash.finalize()))
}

fn valid_id(id: &str, prefix: &str) -> bool {
    id.strip_prefix(prefix).is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The built-in preparation capabilities, keyed by existing parser identifiers.
pub fn manages_parser(parser: &str) -> bool {
    apps::manages_parser(parser)
}

/// Process prepared application targets without reindexing or prompting.
#[allow(clippy::too_many_arguments)]
pub async fn process_recovery_jobs<F>(
    scope: RecoveryScope,
    pool: &SqlitePool,
    fs: &mut F,
    registry: &ParserRegistry,
    session: &mut RecoverySession,
    selected: Option<&[String]>,
    progress: Option<Sender<IndexerEvent>>,
    cancel: Option<Arc<AtomicBool>>,
) -> Result<RecoveryReport>
where
    F: Filesystem + Send,
    F::FileType: FileCommon + Send,
{
    process_recovery_jobs_with(
        &apps::BuiltinPreparation,
        scope,
        pool,
        fs,
        registry,
        session,
        selected,
        progress,
        cancel,
    )
    .await
}

/// Embedders can supply additional preparations while reusing the same journal,
/// validation, bounded parser execution and publication implementation.
#[allow(clippy::too_many_arguments)]
pub async fn process_recovery_jobs_with<F, R>(
    preparation: &R,
    scope: RecoveryScope,
    pool: &SqlitePool,
    fs: &mut F,
    registry: &ParserRegistry,
    session: &mut RecoverySession,
    selected: Option<&[String]>,
    progress: Option<Sender<IndexerEvent>>,
    cancel: Option<Arc<AtomicBool>>,
) -> Result<RecoveryReport>
where
    F: Filesystem + Send,
    F::FileType: FileCommon + Send,
    R: RecoveryPreparation<F>,
{
    ensure!(
        scope.evidence_id > 0 && scope.partition_id > 0,
        "invalid recovery scope"
    );
    ensure!(
        session.limits.input_bytes > 0
            && session.limits.output_bytes > 0
            && session.limits.records > 0
            && session.limits.targets > 0,
        "recovery limits must be positive"
    );
    ensure_schema(pool).await?;
    let inventory = persistence::inventory(pool, scope).await?;
    let parser_ids = sqlx::query_scalar::<_, String>("SELECT DISTINCT parser FROM artifacts WHERE evidence_id=? AND partition_id=? AND parser IS NOT NULL ORDER BY parser")
        .bind(scope.evidence_id).bind(scope.partition_id).fetch_all(pool).await?
        .into_iter().filter(|parser| preparation.supports_parser(parser)).collect::<Vec<_>>();
    let mut jobs = Vec::new();
    let mut offset = 0i64;
    loop {
        if parser_ids.is_empty() {
            break;
        }
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new("SELECT MIN(a.id) AS artifact_id,a.parser,sf.id,sf.identifier,sf.absolute_path,sf.size FROM artifacts a JOIN system_files sf ON sf.id=a.file_id AND sf.evidence_id=a.evidence_id AND sf.partition_id=a.partition_id WHERE a.evidence_id=");
        query
            .push_bind(scope.evidence_id)
            .push(" AND a.partition_id=")
            .push_bind(scope.partition_id)
            .push(" AND a.parser IN (");
        let mut names = query.separated(",");
        for parser in &parser_ids {
            names.push_bind(parser);
        }
        names.push_unseparated(")");
        query
            .push(" GROUP BY sf.id,a.parser ORDER BY MIN(a.id) LIMIT 256 OFFSET ")
            .push_bind(offset);
        let rows = query.build().fetch_all(pool).await?;
        if rows.is_empty() {
            break;
        }
        offset = offset
            .checked_add(i64::try_from(rows.len())?)
            .context("target offset overflow")?;
        for row in rows {
            let source = evidence::source_row(&row, "primary")?;
            let parser_id: String = row.try_get("parser")?;
            let Some(description) = preparation.describe(&parser_id, &source) else {
                continue;
            };
            ensure!(
                jobs.len() < session.limits.targets,
                "recovery target count exceeds the discovery limit"
            );
            let id = scoped_id(
                "recovery-target-",
                scope,
                inventory,
                &format!("{parser_id}:{}", source.path),
            );
            if selected.is_some_and(|ids| !ids.contains(&id)) {
                continue;
            }
            let parser = registry
                .get(parser_id.as_str())
                .context("preparation references an unregistered parser")?;
            let previous = persistence::previous(pool, scope, &id).await?;
            let parameters = previous
                .as_ref()
                .map(|job| job.parameters.clone())
                .unwrap_or_default();
            jobs.push(RecoveryJob {
                scope,
                target_id: id,
                artifact_id: row.try_get("artifact_id")?,
                parser: parser_id,
                application: description.application,
                primary_path: source.path.clone(),
                root_path: description.root_path,
                platform: description.platform,
                inventory_run_id: inventory,
                status: RecoveryStatus::Discovered,
                reason: "target_discovered".into(),
                credentials: previous
                    .as_ref()
                    .map(|job| job.credentials.clone())
                    .unwrap_or_default(),
                inputs: Vec::new(),
                method: None,
                option_specs: parser
                    .option_specs()
                    .iter()
                    .map(RecoveryOptionSpec::try_from)
                    .collect::<std::result::Result<_, _>>()?,
                parameters,
                store_validation: None,
                output_validation: None,
                sources: vec![source],
                object_count: 0,
                issue_count: 0,
                attempt_id: None,
                published_attempt_id: previous.and_then(|job| job.published_attempt_id),
            });
        }
    }
    if let Some(ids) = selected {
        ensure!(
            ids.iter()
                .all(|id| jobs.iter().any(|job| &job.target_id == id)),
            "selected recovery target is outside the current inventory scope"
        );
    }
    session.validate_scope(&RecoveryReport { jobs: jobs.clone() })?;
    persistence::register_jobs(pool, &mut jobs).await?;
    for job in &mut jobs {
        for credential in &mut job.credentials {
            credential.needed = false;
        }
        let result = execution::process_one(
            preparation,
            registry,
            PreparationContext {
                pool,
                filesystem: fs,
                session,
                job,
                cancel: cancel.as_deref(),
            },
            &progress,
        )
        .await;
        if let Err(error) = result {
            if let Some(blocked) = error.downcast_ref::<PreparationFailure>() {
                job.status = blocked.status;
                job.reason = blocked.reason.into();
                if job.status.is_published() || job.status == RecoveryStatus::Discovered {
                    job.status = RecoveryStatus::ValidationFailed;
                    job.reason = "invalid_preparation_failure".into();
                }
                if job.status == RecoveryStatus::AuthenticationFailed {
                    if let Some(credential) = job.credentials.last_mut() {
                        credential.needed = true;
                    }
                }
                persistence::save_attempt(pool, job).await?;
            } else {
                job.status = RecoveryStatus::PersistenceFailed;
                job.reason = "processing_or_persistence_failed".into();
                persistence::save_attempt(pool, job)
                    .await
                    .context("recovery failure could not be journaled")?;
                return Err(error);
            }
        }
        if job.status == RecoveryStatus::Cancelled {
            break;
        }
    }
    Ok(RecoveryReport { jobs })
}
