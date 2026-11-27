#[cfg(unix)]
#[tokio::test]
async fn signature_pass_preserves_links_without_reading_their_contents() {
    use exhume_filesystem::folder_impl::FolderFS;
    use exhume_indexer::{
        ensure_evidence_row, ensure_tables, index_folder_with_report, insert_partition,
        PartitionKind,
    };
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("regular"), b"%PDF-1.7\nfixture").unwrap();
    std::os::unix::fs::symlink("regular", root.path().join("link")).unwrap();
    std::os::unix::fs::symlink("missing", root.path().join("broken")).unwrap();
    std::os::unix::fs::symlink("loop", root.path().join("loop")).unwrap();
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
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
    index_folder_with_report(
        1,
        partition,
        root.path().display().to_string(),
        &pool,
        None,
        None,
    )
    .await
    .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let mut fs = FolderFS::new(root.path().into());
    exhume_indexer::identification::identify_file_types(&mut fs, 1, partition, &pool, Some(tx))
        .await;
    while let Some(event) = rx.recv().await {
        assert!(
            !matches!(
                event.event_type,
                exhume_indexer::IndexerEventType::Issue { .. }
            ),
            "{}",
            event.message
        );
    }
    let links: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM system_files WHERE lower(ftype)='symlink' AND sig_name IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(links, 3);
    let signature: Option<String> =
        sqlx::query_scalar("SELECT sig_name FROM system_files WHERE name='regular'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(signature.is_some_and(|name| !name.is_empty()));
}
