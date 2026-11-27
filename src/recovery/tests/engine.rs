//! Cross-application contract tests. These providers are deliberately unrelated
//! to Signal; real format interoperability stays covered by the app regressions.
use super::*;
use exhume_artefacts::{
    ObjectParsed, Parser, ParserContext, ParserInputReason, ParserIssue, ParserOptionSpec,
    ParserOptionType, ParserOptionValue,
};

const OPTIONS: &[ParserOptionSpec] = &[
    ParserOptionSpec {
        name: "access_token",
        label: "Access token",
        description: "A target-specific secret",
        value_type: ParserOptionType::Secret,
        required: false,
        default: None,
    },
    ParserOptionSpec {
        name: "revision",
        label: "Revision",
        description: "A non-secret parsing option",
        value_type: ParserOptionType::Integer,
        required: false,
        default: None,
    },
];
struct ExampleParser(&'static str);
impl Parser for ExampleParser {
    fn name(&self) -> &'static str {
        self.0
    }
    fn option_specs(&self) -> &'static [ParserOptionSpec] {
        OPTIONS
    }
    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        run_parser_with_options(self, input, ParserOptions::default(), sink, &mut |_| Ok(()))
    }
    fn run_into_with_context(
        &self,
        _input: ParserInput,
        context: &ParserContext,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        _diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
    ) -> Result<()> {
        let expected = self.0.as_bytes();
        if context.require_secret("access_token")? != expected {
            return Err(context
                .request_input("access_token", ParserInputReason::Rejected)
                .into());
        }
        sink(ObjectParsed {
            parser: self.0,
            kind: "test.record",
            text: self.0.into(),
            json: serde_json::json!({"application":self.0,"revision":context.option("revision")}),
        })
    }
}
struct Examples {
    two_stores: bool,
}
impl RecoveryPreparation<FolderFS> for Examples {
    fn describe(&self, parser: &str, primary: &RecoverySource) -> Option<TargetDescription> {
        matches!(parser, "example_a" | "example_b").then(|| TargetDescription {
            application: parser.into(),
            root_path: primary.path.rsplit_once('/').unwrap().0.into(),
            platform: RecoveryPlatform::Linux,
        })
    }
    async fn prepare<'a>(
        &'a self,
        context: PreparationContext<'a, FolderFS>,
    ) -> Result<PreparedParser> {
        let PreparationContext {
            pool,
            filesystem,
            session,
            job,
            cancel,
        } = context;
        let home = job.root_path.rsplit_once('/').unwrap().0.to_owned();
        for store in if self.two_stores {
            vec!["login.store", "application.store"]
        } else {
            vec!["login.store"]
        } {
            let path = format!("{home}/{store}");
            // Acquired-store provenance and identity are shared by both apps.
            let bytes = evidence::read_dependency(
                pool,
                filesystem,
                job,
                &path,
                "credential_store",
                4096,
                cancel,
            )
            .await?
            .context("synthetic store missing")?;
            let id = scoped_id("recovery-store-", job.scope, job.inventory_run_id, &path);
            let password = session.password(job, id, format!("Acquired {store} for {home}"))?;
            if password.expose() != bytes.as_slice() {
                return Err(PreparationFailure {
                    status: RecoveryStatus::AuthenticationFailed,
                    reason: "synthetic_store_rejected",
                }
                .into());
            }
        }
        Ok(PreparedParser {
            options: ParserOptions::default(),
            validation: "example_schema".into(),
        })
    }
}
async fn setup() -> Result<(
    tempfile::TempDir,
    SqlitePool,
    RecoveryScope,
    FolderFS,
    ParserRegistry,
)> {
    let root = tempfile::tempdir()?;
    for user in ["alice", "bob"] {
        let home = root.path().join("home").join(user);
        std::fs::create_dir_all(&home)?;
        std::fs::write(home.join("login.store"), b"synthetic store password\n")?;
        std::fs::write(home.join("application.store"), b"second synthetic password")?;
        for app in ["example_a", "example_b"] {
            std::fs::create_dir_all(home.join(app))?;
            std::fs::write(home.join(app).join("data.bin"), b"synthetic app data")?;
        }
    }
    let (pool, scope, fs, _) = index(root.path()).await?;
    for app in ["example_a", "example_b"] {
        sqlx::query("INSERT INTO artifacts(evidence_id,partition_id,file_id,name,description,parser,tag,category) SELECT evidence_id,partition_id,id,?, '', ?, 'test', 'test' FROM system_files WHERE name='data.bin' AND absolute_path LIKE ?")
            .bind(app).bind(app).bind(format!("%/{app}/data.bin")).execute(&pool).await?;
    }
    let registry = [
        (
            "example_a",
            Arc::new(ExampleParser("example_a")) as Arc<dyn Parser>,
        ),
        (
            "example_b",
            Arc::new(ExampleParser("example_b")) as Arc<dyn Parser>,
        ),
    ]
    .into_iter()
    .collect();
    Ok((root, pool, scope, fs, registry))
}
async fn run(
    preparation: &Examples,
    pool: &SqlitePool,
    scope: RecoveryScope,
    fs: &mut FolderFS,
    registry: &ParserRegistry,
    session: &mut RecoverySession,
) -> Result<RecoveryReport> {
    process_recovery_jobs_with(
        preparation,
        scope,
        pool,
        fs,
        registry,
        session,
        None,
        None,
        None,
    )
    .await
}
#[tokio::test]
async fn unrelated_apps_share_one_store_but_never_another_account_or_target_secret() -> Result<()> {
    let (root, pool, scope, mut fs, registry) = setup().await?;
    let preparation = Examples { two_stores: false };
    let mut session = RecoverySession::default();
    let pending = run(&preparation, &pool, scope, &mut fs, &registry, &mut session).await?;
    assert_eq!(pending.jobs.len(), 4);
    assert_eq!(pending.requests().len(), 2);
    let alice = pending
        .requests()
        .into_iter()
        .find(|request| request.label.contains("/alice"))
        .unwrap();
    assert_eq!(alice.targets.len(), 2);
    session.provide_password(
        &alice.id,
        ParserSecret::new(b"synthetic store password\n".to_vec()),
    )?;
    let inputs = run(&preparation, &pool, scope, &mut fs, &registry, &mut session).await?;
    assert_eq!(
        inputs
            .jobs
            .iter()
            .filter(|job| job.reason == "parser_input_required")
            .count(),
        2
    );
    assert_eq!(inputs.requests().len(), 1);
    let a = inputs
        .jobs
        .iter()
        .find(|job| job.root_path.contains("/alice/") && job.parser == "example_a")
        .unwrap();
    assert_eq!(a.inputs[0].name, "access_token");
    session.provide_secret(
        &a.target_id,
        "access_token",
        ParserSecret::new(b"example_a".to_vec()),
    )?;
    session.provide_target_parameter(&a.target_id, "revision", ParserOptionValue::Integer(7))?;
    let result = run(&preparation, &pool, scope, &mut fs, &registry, &mut session).await?;
    assert_eq!(
        result
            .jobs
            .iter()
            .filter(|job| job.status == RecoveryStatus::Complete)
            .count(),
        1
    );
    let published = result
        .jobs
        .iter()
        .find(|job| job.target_id == a.target_id)
        .unwrap();
    assert_eq!(
        published.parameters["revision"],
        ParserOptionValue::Integer(7)
    );
    assert_eq!(count(&pool, "artifact_objects").await, 1);
    let raw = serde_json::to_string(&result)?;
    assert!(!raw.contains("synthetic store password"));
    let publication = published.published_attempt_id;
    session.provide_secret(
        &a.target_id,
        "access_token",
        ParserSecret::new(b"rejected-secret-must-not-persist".to_vec()),
    )?;
    let rejected = run(&preparation, &pool, scope, &mut fs, &registry, &mut session).await?;
    let a = rejected
        .jobs
        .iter()
        .find(|job| job.target_id == a.target_id)
        .unwrap();
    assert_eq!(a.status, RecoveryStatus::NeedsInput);
    assert_eq!(a.inputs[0].reason, ParserInputReason::Rejected);
    assert_eq!(a.published_attempt_id, publication);
    assert_eq!(count(&pool, "artifact_objects").await, 1);
    assert!(!serde_json::to_string(&a)?.contains("rejected-secret-must-not-persist"));
    assert_eq!(
        std::fs::read(root.path().join("home/alice/login.store"))?,
        b"synthetic store password\n"
    );
    Ok(())
}
#[tokio::test]
async fn sequential_dependencies_and_input_validation_use_the_same_engine() -> Result<()> {
    let (_root, pool, scope, mut fs, registry) = setup().await?;
    let preparation = Examples { two_stores: true };
    let mut session = RecoverySession::default();
    let pending = run(&preparation, &pool, scope, &mut fs, &registry, &mut session).await?;
    let first = pending
        .requests()
        .into_iter()
        .find(|request| request.label.contains("/alice"))
        .unwrap();
    session.provide_password(
        &first.id,
        ParserSecret::new(b"synthetic store password\n".to_vec()),
    )?;
    let second = run(&preparation, &pool, scope, &mut fs, &registry, &mut session).await?;
    let request = second
        .requests()
        .into_iter()
        .find(|request| {
            request.label.contains("application.store") && request.label.contains("/alice")
        })
        .unwrap();
    assert_ne!(request.id, first.id);
    assert_eq!(request.targets.len(), 2);
    session.provide_password(
        &request.id,
        ParserSecret::new(b"second synthetic password".to_vec()),
    )?;
    let waiting = run(&preparation, &pool, scope, &mut fs, &registry, &mut session).await?;
    for job in waiting
        .jobs
        .iter()
        .filter(|job| job.root_path.contains("/alice/"))
    {
        assert_eq!(job.credentials.len(), 2);
        assert!(job.credentials.iter().all(|credential| !credential.needed));
    }
    let alice = waiting
        .jobs
        .iter()
        .find(|job| job.root_path.contains("/alice/"))
        .unwrap();
    session.provide_secret(
        &alice.target_id,
        "undeclared",
        ParserSecret::new(b"private".to_vec()),
    )?;
    assert!(
        run(&preparation, &pool, scope, &mut fs, &registry, &mut session)
            .await
            .is_err()
    );
    assert_eq!(count(&pool, "artifact_objects").await, 0);
    Ok(())
}

#[tokio::test]
async fn reported_cooperative_cancellation_waits_for_the_operation_boundary() -> Result<()> {
    let (_root, pool, scope, _fs, _registry) = setup()
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let mut report = crate::latest_inventory_report(&pool, scope.evidence_id, scope.partition_id)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let operation_cancel = cancel.clone();
    let completed = finished.clone();
    crate::report::run_reported_phase_cooperatively(
        &pool,
        &mut report,
        crate::report::IndexPhase::ArtifactExtraction,
        None,
        Some(cancel),
        |_sender| async move {
            operation_cancel.store(true, Ordering::Relaxed);
            tokio::task::yield_now().await;
            completed.store(true, Ordering::Relaxed);
        },
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    assert!(finished.load(Ordering::Relaxed));
    assert_eq!(report.status, crate::IndexStatus::Cancelled);
    Ok(())
}

struct FilteredExamples(Examples);
impl RecoveryPreparation<FolderFS> for FilteredExamples {
    fn supports_parser(&self, parser: &str) -> bool {
        parser == "example_a"
    }
    fn describe(&self, parser: &str, source: &RecoverySource) -> Option<TargetDescription> {
        assert_eq!(
            parser, "example_a",
            "SQL discovery must exclude unrelated candidates"
        );
        self.0.describe(parser, source)
    }
    async fn prepare(&self, context: PreparationContext<'_, FolderFS>) -> Result<PreparedParser> {
        self.0.prepare(context).await
    }
}
#[tokio::test]
async fn preparation_filter_excludes_unrelated_sources_before_decoding_them() -> Result<()> {
    let (_root, pool, scope, mut fs, registry) = setup().await?;
    // Invalid unrelated source metadata must not prevent managed app recovery.
    sqlx::query("UPDATE system_files SET identifier=-1 WHERE name='application.store'")
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO artifacts(evidence_id,partition_id,file_id,name,description,parser,tag,category) SELECT evidence_id,partition_id,id,'ordinary','','ordinary','test','test' FROM system_files WHERE name='application.store'")
        .execute(&pool).await?;
    let report = process_recovery_jobs_with(
        &FilteredExamples(Examples { two_stores: false }),
        scope,
        &pool,
        &mut fs,
        &registry,
        &mut RecoverySession::default(),
        None,
        None,
        None,
    )
    .await?;
    assert_eq!(report.jobs.len(), 2);
    assert!(report
        .jobs
        .iter()
        .all(|job| job.parser == "example_a" && job.status == RecoveryStatus::NeedsInput));
    Ok(())
}
