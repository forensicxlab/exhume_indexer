use super::{RecoveryReport, RecoverySession};
use anyhow::Result;
/// Adapt the library result to the existing reported-phase/progress contract.
#[allow(clippy::too_many_arguments)]
pub async fn run_reported_recovery<F: exhume_filesystem::Filesystem + Send>(
    pool: &sqlx::SqlitePool,
    fs: &mut F,
    registry: &exhume_artefacts::parsers::ParserRegistry,
    session: &mut RecoverySession,
    report: &mut crate::IndexReport,
    selected: Option<&[String]>,
    ordinary: bool,
    progress: Option<tokio::sync::mpsc::Sender<crate::IndexerEvent>>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<RecoveryReport>
where
    F::FileType: exhume_filesystem::filesystem::FileCommon + Send,
{
    use crate::{
        recovery::{self, RecoveryScope},
        report::{run_reported_phase_cooperatively, IndexIssueCode, IndexPhase},
        IndexerEvent, IndexerEventType,
    };
    let scope = RecoveryScope {
        evidence_id: report.evidence_id,
        partition_id: report.partition_id,
    };
    let mut output = None;
    let output_slot = &mut output;
    let operation_cancel = cancel.clone();
    run_reported_phase_cooperatively(
        pool,
        report,
        IndexPhase::ArtifactExtraction,
        progress,
        Some(cancel.clone()),
        |sender| async move {
            let result = if ordinary {
                crate::artifacts::extract_artefacts_with_recovery(
                    scope.evidence_id,
                    scope.partition_id,
                    pool,
                    fs,
                    registry,
                    session,
                    Some(sender.clone()),
                    Some(operation_cancel.clone()),
                )
                .await
            } else {
                recovery::process_recovery_jobs(
                    scope,
                    pool,
                    fs,
                    registry,
                    session,
                    selected,
                    Some(sender.clone()),
                    Some(operation_cancel.clone()),
                )
                .await
            };
            let result = match result {
                Ok(report) if !ordinary => {
                    recovery::report_recovery_outcomes(pool, &report, Some(sender.clone()))
                        .await
                        .map(|()| report)
                }
                other => other,
            };
            if let Err(error) = &result {
                let _ = sender
                    .send(IndexerEvent {
                        evidence_id: scope.evidence_id,
                        event_type: IndexerEventType::Issue {
                            phase: IndexPhase::ArtifactExtraction,
                            code: IndexIssueCode::PhaseFailure,
                            path: None,
                            record_id: None,
                            fatal: true,
                        },
                        message: format!("Recovery processing stopped: {error}"),
                    })
                    .await;
            }
            *output_slot = Some(result);
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    match output {
        Some(result) => result,
        None if cancel.load(std::sync::atomic::Ordering::Relaxed) => {
            recovery::load_recovery_jobs(pool, scope).await
        }
        None => anyhow::bail!("Recovery processing ended without a result"),
    }
}
