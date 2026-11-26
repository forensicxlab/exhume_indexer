use super::spool::{RecordSpool, StagedRecord, StagedTimeline};
use super::*;
pub(super) async fn process_one<F, R>(
    preparation: &R,
    registry: &ParserRegistry,
    context: PreparationContext<'_, F>,
    progress: &Option<Sender<IndexerEvent>>,
) -> Result<()>
where
    F: Filesystem + Send,
    F::FileType: FileCommon + Send,
    R: RecoveryPreparation<F>,
{
    let PreparationContext {
        pool,
        filesystem: fs,
        session,
        job,
        cancel,
    } = context;
    check_cancel(cancel)?;
    let parser = registry
        .get(job.parser.as_str())
        .ok_or_else(|| blocked(RecoveryStatus::Unsupported, "parser_not_registered"))?;
    job.parameters = session
        .parameters_for(job)
        .map_err(|_| blocked(RecoveryStatus::Malformed, "invalid_parser_parameters"))?;
    let prepared = preparation
        .prepare(PreparationContext {
            pool,
            filesystem: fs,
            session,
            job,
            cancel,
        })
        .await?;
    check_cancel(cancel)?;
    crate::artifacts::send_parser_progress(
        progress,
        job.scope.evidence_id,
        0,
        1,
        parser.name(),
        &job.primary_path,
        job.artifact_id,
        job.sources.first().map(|source| source.system_file_id),
        ParserProgressPhase::Started,
        None,
        None,
        None,
        None,
        None,
        "Parsing prepared recovery target".into(),
    )
    .await;
    let result: Result<()> = async {
        let input = evidence::stage_input(
            pool,
            fs,
            job,
            parser.companion_specs(),
            session.limits.input_bytes,
            cancel,
        )
        .await?;
        let mut options = prepared.options;
        for (name, value) in &job.parameters {
            options.insert(name, value.clone())?;
        }
        session.apply_secrets(job, &mut options)?;
        let mut spool = RecordSpool::new(session.limits.output_bytes, session.limits.records)?;
        let mut diagnostic_spool =
            RecordSpool::new(session.limits.output_bytes, session.limits.records)?;
        let parsed = blocking(|| {
            input.with_input(|input| {
                run_parser_with_options(
                    &**parser,
                    input,
                    options,
                    &mut |record| {
                        check_cancel(cancel)?;
                        let timeline = parser
                            .extract_timeline_events(&record)
                            .into_iter()
                            .map(|event| StagedTimeline {
                                ts: event.ts_unix_ms,
                                event_type: event.event_type.into(),
                                description: event.description,
                                actor: event.actor,
                            })
                            .collect();
                        spool.append(&StagedRecord {
                            kind: record.kind.into(),
                            text: record.text,
                            json: record.json,
                            timeline,
                        })
                    },
                    &mut |issue| {
                        check_cancel(cancel)?;
                        diagnostic_spool.append(&issue)
                    },
                )
            })
        });
        if let Err(error) = parsed {
            if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return Err(blocked(RecoveryStatus::Cancelled, "cancelled"));
            }
            if spool.limit_hit || diagnostic_spool.limit_hit {
                return Err(blocked(
                    RecoveryStatus::LimitExceeded,
                    "record_output_limit",
                ));
            }
            // A callback I/O failure is a staging failure, not a bad credential.
            if spool.io_failed || diagnostic_spool.io_failed {
                return Err(error.context("Recovery record spool failed"));
            }
            if let Some(exhume_artefacts::ParserInputError::NeedsInput { requests }) =
                error.downcast_ref::<exhume_artefacts::ParserInputError>()
            {
                // Only declared inputs may be surfaced by a preparation parser.
                if requests.len() <= job.option_specs.len()
                    && requests.iter().all(|request| {
                        job.option_specs.iter().any(|spec| {
                            spec.name == request.name && spec.value_type == request.value_type
                        })
                    })
                {
                    job.inputs = requests
                        .iter()
                        .filter_map(|request| {
                            job.option_specs
                                .iter()
                                .find(|spec| spec.name == request.name)
                                .map(|spec| exhume_artefacts::ParserInputRequest {
                                    name: spec.name.clone(),
                                    label: spec.label.clone(),
                                    description: spec.description.clone(),
                                    value_type: spec.value_type,
                                    reason: request.reason,
                                })
                        })
                        .collect();
                    return Err(blocked(RecoveryStatus::NeedsInput, "parser_input_required"));
                }
            }
            return Err(blocked(
                RecoveryStatus::ValidationFailed,
                "parser_validation_failed",
            ));
        }
        check_cancel(cancel)?;
        job.object_count = spool.count;
        job.output_validation = Some(prepared.validation);
        job.issue_count = diagnostic_spool.count;
        job.status = if job.issue_count == 0 {
            RecoveryStatus::Complete
        } else {
            RecoveryStatus::Partial
        };
        job.reason = if job.issue_count == 0 {
            "parsed"
        } else {
            "record_diagnostics"
        }
        .into();
        persistence::publish(
            pool,
            job,
            parser.name(),
            spool.finish()?,
            diagnostic_spool.finish()?,
            cancel,
        )
        .await?;
        crate::artifacts::send_parser_progress(
            progress,
            job.scope.evidence_id,
            1,
            1,
            parser.name(),
            &job.primary_path,
            job.artifact_id,
            job.sources.first().map(|source| source.system_file_id),
            ParserProgressPhase::Completed,
            None,
            None,
            None,
            None,
            Some(job.object_count),
            format!(
                "Recovery target parsed: {} objects, {} issues",
                job.object_count, job.issue_count
            ),
        )
        .await;
        Ok(())
    }
    .await;
    if result.is_err() && !cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        crate::artifacts::send_parser_progress(
            progress,
            job.scope.evidence_id,
            1,
            1,
            parser.name(),
            &job.primary_path,
            job.artifact_id,
            job.sources.first().map(|source| source.system_file_id),
            ParserProgressPhase::Failed,
            None,
            None,
            None,
            None,
            Some(0),
            "Recovery target was not published; prior results were retained".into(),
        )
        .await;
    }
    result
}
