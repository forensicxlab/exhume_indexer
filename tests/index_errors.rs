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
