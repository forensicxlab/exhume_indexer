//! Public entry points must expose failures even without progress subscribers.
use exhume_filesystem::folder_impl::FolderFS;
use exhume_indexer::{artifacts::extract_artefacts, ensure_tables, index_filesystem, index_folder};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::{atomic::AtomicBool, Arc};

#[tokio::test]
async fn indexing_returns_database_failures_without_a_progress_receiver() {
    let root = tempfile::tempdir().unwrap();
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    pool.close().await;
    let mut fs = FolderFS::new(root.path().to_path_buf());
    assert!(index_filesystem(&mut fs, 1, 1, &pool, None, None, None)
        .await
        .is_err());
    assert!(
        index_folder(1, 1, root.path().display().to_string(), &pool, None, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn extraction_returns_database_failures_without_a_progress_receiver() {
    let root = tempfile::tempdir().unwrap();
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    pool.close().await;
    let mut fs = FolderFS::new(root.path().to_path_buf());
    let registry = exhume_artefacts::parsers::build_registry();
    assert!(
        extract_artefacts(1, 1, &pool, &mut fs, &registry, None, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn folder_indexing_returns_cancellation_without_a_progress_receiver() {
    let root = tempfile::tempdir().unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    ensure_tables(&pool).await.unwrap();
    let error = index_folder(
        1,
        1,
        root.path().display().to_string(),
        &pool,
        None,
        Some(Arc::new(AtomicBool::new(true))),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("cancelled"));
}

#[tokio::test]
async fn successful_recovery_does_not_clear_incomplete_analysis_or_its_cause() {
    use exhume_indexer::{
        ensure_evidence_row, index_folder_with_report, insert_partition,
        recovery::{run_reported_recovery, RecoverySession},
        IndexStatus, PartitionKind,
    };
    let root = tempfile::tempdir().unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    ensure_tables(&pool).await.unwrap();
    ensure_evidence_row(&pool, 1, root.path().to_str().unwrap(), true)
        .await
        .unwrap();
    let partition = insert_partition(&pool, 1, PartitionKind::Folder, 0, 0, 0, 0, None)
        .await
        .unwrap();
    let mut report = index_folder_with_report(
        1,
        partition,
        root.path().display().to_string(),
        &pool,
        None,
        None,
    )
    .await
    .unwrap();
    let mut fs = FolderFS::new(root.path().to_path_buf());
    let registry = exhume_artefacts::parsers::build_registry();
    for previous in [
        IndexStatus::Cancelled,
        IndexStatus::Failed,
        IndexStatus::Aborted,
    ] {
        report.status = previous;
        sqlx::query("UPDATE index_runs SET status=?,report_json=?,error='Original incomplete analysis' WHERE id=?")
            .bind(previous.as_str()).bind(serde_json::to_string(&report).unwrap()).bind(report.run_id)
            .execute(&pool).await.unwrap();
        let recovered = run_reported_recovery(
            &pool,
            &mut fs,
            &registry,
            &mut RecoverySession::default(),
            &mut report,
            None,
            false,
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
        assert!(recovered.jobs.is_empty());
        assert_eq!(report.status, previous);
        let persisted = exhume_indexer::report::load_index_report(&pool, report.run_id)
            .await
            .unwrap();
        assert_eq!(persisted.status, previous);
        let cause: String = sqlx::query_scalar("SELECT error FROM index_runs WHERE id=?")
            .bind(report.run_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(cause, "Original incomplete analysis");
    }
}
