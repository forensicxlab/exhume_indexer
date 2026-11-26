use super::*;

#[tokio::test]
async fn development_journals_require_a_rebuild_without_modification() -> Result<()> {
    for table in ["signal_jobs", "signal_attempts", "signal_diagnostics"] {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        sqlx::query(&format!("CREATE TABLE {table}(details_json TEXT)"))
            .execute(&pool)
            .await?;
        sqlx::query(&format!("INSERT INTO {table} VALUES('retained')"))
            .execute(&pool)
            .await?;
        let error = ensure_schema(&pool).await.unwrap_err();
        assert!(error.to_string().contains("rebuild the derived index"));
        assert_eq!(count(&pool, table).await, 1);
        let created: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'recovery_%'")
                .fetch_one(&pool)
                .await?;
        assert_eq!(created, 0);
    }
    Ok(())
}

#[tokio::test]
async fn unknown_recovery_versions_are_rejected_without_changes() -> Result<()> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    ensure_schema(&pool).await?;
    ensure_schema(&pool).await?;
    sqlx::query("UPDATE recovery_schema SET version=99")
        .execute(&pool)
        .await?;
    assert!(ensure_schema(&pool).await.is_err());
    let version: i64 = sqlx::query_scalar("SELECT version FROM recovery_schema")
        .fetch_one(&pool)
        .await?;
    assert_eq!(version, 99);
    Ok(())
}

#[tokio::test]
async fn obsolete_asset_catalogues_are_rejected_without_changes() -> Result<()> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    sqlx::query("CREATE TABLE artifact_asset_state(id INTEGER PRIMARY KEY,generation TEXT)")
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO artifact_asset_state VALUES(1,'original')")
        .execute(&pool)
        .await?;
    sqlx::query(
        "CREATE TABLE artifact_assets(asset_id TEXT PRIMARY KEY,profile_id TEXT,details_json TEXT)",
    )
    .execute(&pool)
    .await?;
    sqlx::query("INSERT INTO artifact_assets VALUES('old','old','{}')")
        .execute(&pool)
        .await?;
    let error = crate::assets::ensure_schema(&pool).await.unwrap_err();
    assert!(error.to_string().contains("rebuild the derived index"));
    assert_eq!(count(&pool, "artifact_assets").await, 1);
    let generation: String = sqlx::query_scalar("SELECT generation FROM artifact_asset_state")
        .fetch_one(&pool)
        .await?;
    assert_eq!(generation, "original");
    Ok(())
}
