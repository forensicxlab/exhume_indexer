use super::*;
use exhume_artefacts::parsers::build_registry;
use exhume_filesystem::folder_impl::FolderFS;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteConnection, SqlitePoolOptions},
    Connection,
};
use std::path::Path;

mod assets;
mod engine;
mod schema;

#[cfg(feature = "sqlcipher")]
mod linux;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_can_run_in_a_spawned_multithread_task() -> Result<()> {
    let root = tempfile::tempdir()?;
    database(
        &root.path().join("home/alice/.config/Signal/sql/db.sqlite"),
        false,
        false,
    )
    .await?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let result = tokio::spawn(async move {
        process(&pool, scope, &mut fs, &mut RecoverySession::default()).await
    })
    .await??;
    assert_eq!(result.jobs.len(), 1);
    assert_eq!(result.jobs[0].status, RecoveryStatus::Complete);
    assert_eq!(result.jobs[0].object_count, 6);
    Ok(())
}

#[tokio::test]
async fn linux_catalogue_discovers_packages_flatpak_and_root_profiles() -> Result<()> {
    for path in [
        "home/alice/.config/Signal",
        "home/alice/.config/Signal Beta",
        "home/alice/.config/Signal AppImage",
        "home/alice/.config/Signal Beta AppImage",
        "home/alice/.var/app/org.signal.Signal/config/Signal",
        "root/.config/Signal",
        "volume_2/home/alice/.config/Signal Beta AppImage",
    ] {
        let root = tempfile::tempdir()?;
        database(&root.path().join(path).join("sql/db.sqlite"), false, false).await?;
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        let parsed = process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
        assert_eq!(parsed.jobs.len(), 1, "{path}");
        assert_eq!(parsed.jobs[0].platform, RecoveryPlatform::Linux, "{path}");
        assert_eq!(parsed.jobs[0].status, RecoveryStatus::Complete);
    }
    Ok(())
}

const SCHEMA: &str = include_str!("fixtures/schema.sql");
fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/signal-keys.json")).unwrap()
}

async fn database(path: &Path, encrypted: bool, malformed: bool) -> Result<()> {
    database_compatibility(path, encrypted, malformed, 4).await
}
async fn database_compatibility(
    path: &Path,
    encrypted: bool,
    malformed: bool,
    compatibility: u8,
) -> Result<()> {
    std::fs::create_dir_all(path.parent().unwrap())?;
    let mut connection = SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true),
    )
    .await?;
    if encrypted {
        let key = vectors()["database_key"].as_str().unwrap().to_string();
        sqlx::raw_sql(&format!(
            "PRAGMA key=\"x'{key}'\"; PRAGMA cipher_compatibility={compatibility};"
        ))
        .execute(&mut connection)
        .await?;
    }
    sqlx::raw_sql(SCHEMA).execute(&mut connection).await?;
    if malformed {
        sqlx::query("UPDATE messages SET json='{damaged' WHERE id='m1'")
            .execute(&mut connection)
            .await?;
    }
    connection.close().await?;
    Ok(())
}

async fn index(root: &Path) -> Result<(SqlitePool, RecoveryScope, FolderFS, crate::IndexReport)> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    crate::ensure_tables(&pool).await?;
    crate::ensure_evidence_row(&pool, 1, root.to_str().unwrap(), true).await?;
    let partition =
        crate::insert_partition(&pool, 1, crate::PartitionKind::Folder, 0, 0, 0, 0, None).await?;
    let report = crate::index_folder_with_report(
        1,
        partition,
        root.to_str().unwrap().into(),
        &pool,
        None,
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    crate::artifacts::identify_artefacts(1, partition, &pool, None, None).await;
    Ok((
        pool,
        RecoveryScope {
            evidence_id: 1,
            partition_id: partition,
        },
        FolderFS::new(root.into()),
        report,
    ))
}

async fn process(
    pool: &SqlitePool,
    scope: RecoveryScope,
    fs: &mut FolderFS,
    session: &mut RecoverySession,
) -> Result<RecoveryReport> {
    process_recovery_jobs(
        scope,
        pool,
        fs,
        &build_registry(),
        session,
        None,
        None,
        None,
    )
    .await
}
async fn count(pool: &SqlitePool, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn truncated_databases_do_not_request_credentials_or_a_cipher_backend() -> Result<()> {
    for length in [0, 15, 16, 511] {
        let root = tempfile::tempdir()?;
        let path = root
            .path()
            .join("Users/alice/AppData/Roaming/Signal/sql/db.sqlite");
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, vec![0xa5; length])?;
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        let report = process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
        assert_eq!(report.jobs.len(), 1);
        assert_eq!(report.jobs[0].status, RecoveryStatus::Malformed);
        assert!(report.requests().is_empty());
        assert_eq!(report.jobs[0].sources.len(), 1);
        assert_eq!(count(&pool, "artifact_objects").await, 0);
    }
    Ok(())
}

#[tokio::test]
async fn plaintext_discovery_scoped_attachment_links_and_repeat_publication() -> Result<()> {
    let root = tempfile::tempdir()?;
    let profile = root.path().join("home/alice/.config/Signal");
    database(&profile.join("sql/db.sqlite"), false, false).await?;
    // Plaintext evidence bypasses even a damaged configuration.
    std::fs::write(profile.join("config.json"), b"damaged")?;
    std::fs::create_dir_all(profile.join("attachments.noindex/ab"))?;
    std::fs::write(profile.join("attachments.noindex/ab/photo"), b"PNG")?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let mut session = RecoverySession::default();
    let report = process(&pool, scope, &mut fs, &mut session).await?;
    assert_eq!(report.jobs.len(), 1);
    assert_eq!(report.jobs[0].status, RecoveryStatus::Complete);
    assert_eq!(report.jobs[0].method.as_deref(), Some("plaintext_database"));
    assert_eq!(count(&pool, "artifact_objects").await, 6);
    let resolved: String =
        sqlx::query_scalar("SELECT resolved_absolute_path FROM artifact_attachment_refs")
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        resolved,
        "/home/alice/.config/Signal/attachments.noindex/ab/photo"
    );
    let objects = count(&pool, "artifact_objects").await;
    let timeline = count(&pool, "timeline_events").await;
    process(&pool, scope, &mut fs, &mut session).await?;
    assert_eq!(count(&pool, "artifact_objects").await, objects);
    assert_eq!(count(&pool, "timeline_events").await, timeline);
    assert_eq!(count(&pool, "artifact_attachment_refs").await, 1);
    assert_eq!(count(&pool, "recovery_attempts").await, 2);
    Ok(())
}

#[tokio::test]
async fn diagnostics_limits_cancellation_and_failed_database_write_preserve_publication(
) -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("home/alice/.config/Signal/sql/db.sqlite");
    database(&path, false, true).await?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let before = std::fs::read(&path)?;
    let mut session = RecoverySession::default();
    let report = process(&pool, scope, &mut fs, &mut session).await?;
    let published = report.jobs[0].published_attempt_id;
    assert_eq!(report.jobs[0].status, RecoveryStatus::Partial);
    assert_eq!(report.jobs[0].issue_count, 1);
    let issue: String = sqlx::query_scalar("SELECT issue_json FROM recovery_diagnostics")
        .fetch_one(&pool)
        .await?;
    let issue: ParserIssue = serde_json::from_str(&issue)?;
    assert_eq!(issue.unit, Some(1));
    assert!(issue.message.contains("messages"));
    let objects = count(&pool, "artifact_objects").await;
    session.limits.records = 1;
    let limited = process(&pool, scope, &mut fs, &mut session).await?;
    assert_eq!(limited.jobs[0].status, RecoveryStatus::LimitExceeded);
    assert_eq!(limited.jobs[0].published_attempt_id, published);
    assert_eq!(count(&pool, "artifact_objects").await, objects);
    session.limits = RecoveryLimits::default();
    let cancelled = process_recovery_jobs(
        scope,
        &pool,
        &mut fs,
        &build_registry(),
        &mut session,
        None,
        None,
        Some(Arc::new(AtomicBool::new(true))),
    )
    .await?;
    assert_eq!(cancelled.jobs[0].status, RecoveryStatus::Cancelled);
    assert_eq!(count(&pool, "artifact_objects").await, objects);
    sqlx::raw_sql("CREATE TRIGGER fail_signal_insert BEFORE INSERT ON artifact_objects BEGIN SELECT RAISE(ABORT,'synthetic persistence failure'); END;").execute(&pool).await?;
    assert!(process(&pool, scope, &mut fs, &mut session).await.is_err());
    assert_eq!(count(&pool, "artifact_objects").await, objects);
    assert_eq!(std::fs::read(path)?, before);
    Ok(())
}

#[tokio::test]
async fn old_inventory_ids_and_cross_scope_requests_are_rejected() -> Result<()> {
    let root = tempfile::tempdir()?;
    database(
        &root.path().join("home/alice/.config/Signal/sql/db.sqlite"),
        false,
        false,
    )
    .await?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let mut session = RecoverySession::default();
    let report = process(&pool, scope, &mut fs, &mut session).await?;
    let selected = vec![report.jobs[0].target_id.clone()];
    let wrong = RecoveryScope {
        evidence_id: 99,
        ..scope
    };
    assert!(process_recovery_jobs(
        wrong,
        &pool,
        &mut fs,
        &build_registry(),
        &mut session,
        Some(&selected),
        None,
        None
    )
    .await
    .is_err());
    sqlx::query(
        "UPDATE index_inventory SET run_id=run_id+100 WHERE evidence_id=? AND partition_id=?",
    )
    .bind(scope.evidence_id)
    .bind(scope.partition_id)
    .execute(&pool)
    .await?;
    assert!(process_recovery_jobs(
        scope,
        &pool,
        &mut fs,
        &build_registry(),
        &mut session,
        Some(&selected),
        None,
        None
    )
    .await
    .is_err());
    Ok(())
}

#[cfg(not(feature = "sqlcipher"))]
#[tokio::test]
async fn missing_backend_is_reported_before_any_credential_request() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root
        .path()
        .join("Users/alice/Library/Application Support/Signal/sql/db.sqlite");
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(path, [7; 4096])?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let report = process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
    assert_eq!(report.jobs[0].status, RecoveryStatus::BackendUnavailable);
    assert!(report.requests().is_empty());
    Ok(())
}

#[cfg(feature = "sqlcipher")]
async fn windows(root: &Path, direct: bool) -> Result<()> {
    let values = vectors();
    let home = root.join("Users/alice/AppData/Roaming");
    let profile = home.join("Signal");
    database(&profile.join("sql/db.sqlite"), true, false).await?;
    std::fs::write(
        profile.join("config.json"),
        serde_json::to_vec(
            &values[if direct {
                "windows_direct_config"
            } else {
                "windows_config"
            }],
        )?,
    )?;
    std::fs::write(
        profile.join("Local State"),
        serde_json::to_vec(&values["windows_local_state"])?,
    )?;
    let protect = home
        .join("Microsoft/Protect")
        .join(values["windows_sid"].as_str().unwrap());
    std::fs::create_dir_all(&protect)?;
    std::fs::write(
        protect.join(values["master_key_guid"].as_str().unwrap()),
        hex::decode(values["master_key_file"].as_str().unwrap())?,
    )?;
    Ok(())
}

#[cfg(feature = "sqlcipher")]
#[tokio::test]
async fn native_windows_paths_preserve_sources_and_resolve_dpapi_and_media() -> Result<()> {
    for direct in [false, true] {
        let root = tempfile::tempdir()?;
        windows(root.path(), direct).await?;
        let media = root
            .path()
            .join("Users/alice/AppData/Roaming/Signal/attachments.noindex/ab");
        std::fs::create_dir_all(&media)?;
        std::fs::write(media.join("photo"), b"SYNTHETIC IMAGE")?;
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        // Keep the fixture's inode-to-file mapping while representing evidence
        // paths exactly as a native NTFS inventory does.
        fs.enumerate_all_files()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        sqlx::query("UPDATE system_files SET absolute_path=replace(absolute_path,'/',char(92))")
            .execute(&pool)
            .await?;
        crate::artifacts::identify_artefacts(
            scope.evidence_id,
            scope.partition_id,
            &pool,
            None,
            None,
        )
        .await;
        let metadata: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM artifacts WHERE parser='windows_dpapi_masterkey'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(metadata, 1);
        let mut session = RecoverySession::default();
        let pending = process(&pool, scope, &mut fs, &mut session).await?;
        assert_eq!(pending.jobs.len(), 1);
        assert_eq!(pending.jobs[0].status, RecoveryStatus::NeedsInput);
        session.provide_password(
            &pending.requests()[0].id,
            ParserSecret::new(
                vectors()["windows_password"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            ),
        )?;
        let parsed = process(&pool, scope, &mut fs, &mut session).await?;
        let job = &parsed.jobs[0];
        assert_eq!(job.status, RecoveryStatus::Complete);
        assert_eq!(job.object_count, 6);
        assert_eq!(job.inventory_run_id, pending.jobs[0].inventory_run_id);
        assert!(job.sources.iter().all(|s| s.path.starts_with('\\')));
        assert!(job.sources.iter().all(|s| s.sha256.is_some()));
        let source: String = sqlx::query_scalar(
            "SELECT json_extract(json,'$.source.path') FROM artifact_objects WHERE parser='desktop_signal' LIMIT 1",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(source, job.primary_path);
        let resolved: String =
            sqlx::query_scalar("SELECT resolved_absolute_path FROM artifact_attachment_refs")
                .fetch_one(&pool)
                .await?;
        assert_eq!(
            resolved,
            r"\Users\alice\AppData\Roaming\Signal\attachments.noindex\ab\photo"
        );
    }
    Ok(())
}

#[cfg(feature = "sqlcipher")]
#[tokio::test]
async fn windows_password_retry_and_direct_dpapi_are_atomic_and_redacted() -> Result<()> {
    for direct in [false, true] {
        let root = tempfile::tempdir()?;
        windows(root.path(), direct).await?;
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        let mut session = RecoverySession::default();
        let waiting = process(&pool, scope, &mut fs, &mut session).await?;
        assert_eq!(waiting.jobs[0].status, RecoveryStatus::NeedsInput);
        let requests = waiting.requests();
        assert_eq!(requests.len(), 1);
        session.provide_password(
            &requests[0].id,
            ParserSecret::new(b"wrong-credential".to_vec()),
        )?;
        let failed = process(&pool, scope, &mut fs, &mut session).await?;
        assert_eq!(failed.jobs[0].status, RecoveryStatus::AuthenticationFailed);
        assert_eq!(count(&pool, "artifact_objects").await, 0);
        let password = vectors()["windows_password"].as_str().unwrap().to_string();
        session.provide_password(
            &requests[0].id,
            ParserSecret::new(password.as_bytes().to_vec()),
        )?;
        let recovered = process(&pool, scope, &mut fs, &mut session).await?;
        assert_eq!(recovered.jobs[0].status, RecoveryStatus::Complete);
        assert_eq!(
            recovered.jobs[0].store_validation.as_deref(),
            Some("dpapi_master_key_and_blob")
        );
        let published = recovered.jobs[0].published_attempt_id;
        let objects = count(&pool, "artifact_objects").await;
        session.provide_password(&requests[0].id, ParserSecret::new(b"wrong-again".to_vec()))?;
        let failed = process(&pool, scope, &mut fs, &mut session).await?;
        assert_eq!(failed.jobs[0].published_attempt_id, published);
        assert_eq!(count(&pool, "artifact_objects").await, objects);
        let json = serde_json::to_string(&failed)?;
        for secret in [
            password.as_str(),
            vectors()["database_key"].as_str().unwrap(),
            "wrong-again",
        ] {
            assert!(!json.contains(secret));
        }
    }
    Ok(())
}

#[cfg(feature = "sqlcipher")]
async fn macos(root: &Path, indirect: bool, companion: bool) -> Result<()> {
    let profile = root.join("Users/alice/Library/Application Support/Signal");
    database(&profile.join("sql/db.sqlite"), true, false).await?;
    let values = vectors();
    std::fs::write(
        profile.join("config.json"),
        serde_json::to_vec(&values["macos_config"])?,
    )?;
    let mut bytes = include_bytes!("fixtures/signal-macos.keychain-db").to_vec();
    if indirect {
        let offset = exhume_artefacts::formats::keychain::LegacyKeychain::parse(&bytes)?
            .metadata()
            .database_blob_offset
            .unwrap();
        let blob = hex::decode(values["macos_indirect_blob"].as_str().unwrap())?;
        bytes[offset..offset + blob.len()].copy_from_slice(&blob);
    }
    let keychains = root.join("Users/alice/Library/Keychains");
    std::fs::create_dir_all(&keychains)?;
    std::fs::write(keychains.join("login.keychain-db"), &bytes)?;
    if companion {
        let salt = exhume_artefacts::formats::keychain::LegacyKeychain::parse(&bytes)?
            .protected_entropy_identifier()
            .unwrap();
        let directory = root.join("private/var/db/SystemKeys");
        std::fs::create_dir_all(&directory)?;
        plist::Value::Data(hex::decode(values["protected_entropy"].as_str().unwrap())?)
            .to_file_xml(directory.join(salt))?;
    }
    Ok(())
}

#[cfg(feature = "sqlcipher")]
#[tokio::test]
async fn macos_systemkeys_hex_case_is_scoped_and_ambiguous_names_stay_unresolved() -> Result<()> {
    for ambiguous in [false, true] {
        let root = tempfile::tempdir()?;
        macos(root.path(), true, true).await?;
        let bytes = std::fs::read(
            root.path()
                .join("Users/alice/Library/Keychains/login.keychain-db"),
        )?;
        let salt = exhume_artefacts::formats::keychain::LegacyKeychain::parse(&bytes)?
            .protected_entropy_identifier()
            .unwrap();
        let directory = root.path().join("private/var/db/SystemKeys");
        let uppercase = salt.to_ascii_uppercase();
        assert_ne!(salt, uppercase);
        std::fs::rename(directory.join(&salt), directory.join(&uppercase))?;
        // Another volume's identically named file is never a candidate.
        let other = root.path().join("volume_5/private/var/db/SystemKeys");
        std::fs::create_dir_all(&other)?;
        std::fs::write(other.join(&salt), b"SYNTHETIC unrelated volume")?;
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        if ambiguous {
            // Model a case-sensitive evidence volume even when the host test
            // filesystem cannot create distinct uppercase/lowercase names.
            sqlx::query("INSERT INTO system_files(evidence_id,partition_id,identifier,absolute_path,name,ftype,size,path_key,is_dir,metadata) SELECT evidence_id,partition_id,identifier+1,?,?,ftype,size,path_key || '-synthetic-case-variant',is_dir,metadata FROM system_files WHERE absolute_path=?")
                .bind(format!("/private/var/db/SystemKeys/{salt}"))
                .bind(&salt)
                .bind(format!("/private/var/db/SystemKeys/{uppercase}"))
                .execute(&pool)
                .await?;
        }
        let mut session = RecoverySession::default();
        let pending = process(&pool, scope, &mut fs, &mut session).await?;
        if ambiguous {
            assert_eq!(pending.jobs[0].status, RecoveryStatus::MissingEvidence);
            assert_eq!(pending.jobs[0].reason, "systemkeys_companion_ambiguous");
            assert!(pending.requests().is_empty());
            continue;
        }
        assert_eq!(pending.jobs[0].status, RecoveryStatus::NeedsInput);
        let source = pending.jobs[0]
            .sources
            .iter()
            .find(|source| source.role == "protected_entropy")
            .unwrap();
        assert_eq!(
            source.path,
            format!("/private/var/db/SystemKeys/{uppercase}")
        );
        session.provide_password(
            &pending.requests()[0].id,
            ParserSecret::new(
                vectors()["macos_login_password"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            ),
        )?;
        let recovered = process(&pool, scope, &mut fs, &mut session).await?;
        assert_eq!(recovered.jobs[0].status, RecoveryStatus::Complete);
        assert_eq!(
            recovered.jobs[0].method.as_deref(),
            Some("keychain_login_password_protected_entropy")
        );
        assert!(recovered.jobs[0]
            .sources
            .iter()
            .all(|source| !source.path.starts_with("/volume_5/")));
    }
    Ok(())
}

#[cfg(feature = "sqlcipher")]
#[tokio::test]
async fn macos_direct_and_indirect_routes_continue_past_pending_profiles() -> Result<()> {
    for indirect in [false, true] {
        let root = tempfile::tempdir()?;
        macos(root.path(), indirect, true).await?;
        database(
            &root.path().join("home/bob/.config/Signal/sql/db.sqlite"),
            false,
            false,
        )
        .await?;
        let (pool, scope, mut fs, mut index_report) = index(root.path()).await?;
        let mut session = RecoverySession::default();
        let pending = crate::artifacts::extract_artefacts_with_recovery(
            scope.evidence_id,
            scope.partition_id,
            &pool,
            &mut fs,
            &build_registry(),
            &mut session,
            None,
            None,
        )
        .await?;
        assert_eq!(pending.unresolved_count(), 1);
        assert!(
            count(&pool, "artifact_objects").await > 6,
            "ordinary Keychain metadata and Bob's profile should be parsed"
        );
        let request = pending.requests().remove(0);
        let password = vectors()[if indirect {
            "macos_login_password"
        } else {
            "macos_password"
        }]
        .as_str()
        .unwrap()
        .to_string();
        session.provide_password(&request.id, ParserSecret::new(password.into_bytes()))?;
        let selected = request.targets;
        let recovered = process_recovery_jobs(
            scope,
            &pool,
            &mut fs,
            &build_registry(),
            &mut session,
            Some(&selected),
            None,
            None,
        )
        .await?;
        assert_eq!(recovered.jobs[0].status, RecoveryStatus::Complete);
        assert_eq!(
            recovered.jobs[0]
                .sources
                .iter()
                .find(|s| s.role == "login_keychain")
                .unwrap()
                .record_offsets
                .len(),
            2
        );
        assert_eq!(current_issue_count(&pool, scope).await?, 0);
        crate::report::run_reported_phase(
            &pool,
            &mut index_report,
            crate::report::IndexPhase::ArtifactExtraction,
            None,
            None,
            |_| async {},
        )
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        assert_eq!(index_report.status, crate::IndexStatus::Complete);
        assert_eq!(index_report.recovery_issues, 0);
    }
    Ok(())
}

#[cfg(feature = "sqlcipher")]
#[tokio::test]
async fn missing_systemkeys_preserves_uncertainty_and_raw_key_bypasses_missing_inputs() -> Result<()>
{
    let root = tempfile::tempdir()?;
    macos(root.path(), true, false).await?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let mut session = RecoverySession::default();
    let pending = process(&pool, scope, &mut fs, &mut session).await?;
    let request = &pending.requests()[0];
    session.provide_password(
        &request.id,
        ParserSecret::new(
            vectors()["macos_login_password"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
    )?;
    let blocked = process(&pool, scope, &mut fs, &mut session).await?;
    assert_eq!(blocked.jobs[0].status, RecoveryStatus::MissingEvidence);
    assert_eq!(
        blocked.jobs[0].reason,
        "direct_authentication_failed_systemkeys_companion_missing"
    );
    session.provide_secret(
        &blocked.jobs[0].target_id,
        "database_key",
        ParserSecret::new(
            vectors()["database_key"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
    )?;
    let recovered = process(&pool, scope, &mut fs, &mut session).await?;
    assert_eq!(recovered.jobs[0].status, RecoveryStatus::Complete);
    assert_eq!(
        recovered.jobs[0].method.as_deref(),
        Some("provided_database_key")
    );
    Ok(())
}

#[cfg(feature = "sqlcipher")]
#[tokio::test]
async fn provided_linux_keys_preserve_explicit_cipher_3_selection() -> Result<()> {
    let root = tempfile::tempdir()?;
    let profile = root.path().join("home/alice/.config/Signal");
    database_compatibility(&profile.join("sql/db.sqlite"), true, false, 3).await?;
    std::fs::write(
        profile.join("config.json"),
        serde_json::to_vec(
            &serde_json::from_str::<serde_json::Value>(include_str!("fixtures/linux-values.json"))?
                ["v11_config"],
        )?,
    )?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let mut session = RecoverySession::default();
    let pending = process(&pool, scope, &mut fs, &mut session).await?;
    assert_eq!(pending.jobs[0].status, RecoveryStatus::MissingEvidence);
    assert!(pending.requests().is_empty());
    session.provide_secret(
        &pending.jobs[0].target_id,
        "database_key",
        ParserSecret::new(
            vectors()["database_key"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
    )?;
    let failed = process(&pool, scope, &mut fs, &mut session).await?;
    assert_eq!(failed.jobs[0].status, RecoveryStatus::ValidationFailed);
    assert_eq!(count(&pool, "artifact_objects").await, 0);
    session.provide_parameter(
        "desktop_signal",
        "cipher_version",
        exhume_artefacts::ParserOptionValue::Integer(3),
    )?;
    let recovered = process(&pool, scope, &mut fs, &mut session).await?;
    assert_eq!(recovered.jobs[0].status, RecoveryStatus::Complete);
    assert_eq!(
        recovered.jobs[0].parameters["cipher_version"],
        exhume_artefacts::ParserOptionValue::Integer(3)
    );
    Ok(())
}

#[tokio::test]
async fn catalogue_aliases_do_not_duplicate_profile_jobs() -> Result<()> {
    let root = tempfile::tempdir()?;
    database(
        &root.path().join("home/alice/.config/Signal/sql/db.sqlite"),
        false,
        false,
    )
    .await?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    sqlx::query("INSERT INTO artifacts(evidence_id,file_id,partition_id,name,description,parser,tag,category) SELECT evidence_id,file_id,partition_id,name||' alias',description,parser,tag,category FROM artifacts WHERE parser='desktop_signal'").execute(&pool).await?;
    let report = process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
    assert_eq!(report.jobs.len(), 1);
    assert_eq!(count(&pool, "artifact_objects").await, 6);
    Ok(())
}

#[tokio::test]
async fn cancellation_retains_unstarted_profiles_for_a_new_session() -> Result<()> {
    let root = tempfile::tempdir()?;
    for user in ["alice", "bob"] {
        database(
            &root
                .path()
                .join(format!("home/{user}/.config/Signal/sql/db.sqlite")),
            false,
            false,
        )
        .await?;
    }
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    process_recovery_jobs(
        scope,
        &pool,
        &mut fs,
        &build_registry(),
        &mut RecoverySession::default(),
        None,
        None,
        Some(Arc::new(AtomicBool::new(true))),
    )
    .await?;
    let pending = load_recovery_jobs(&pool, scope).await?;
    assert_eq!(pending.jobs.len(), 2);
    assert!(pending
        .jobs
        .iter()
        .any(|job| job.status == RecoveryStatus::Discovered));
    let selected: Vec<_> = pending
        .jobs
        .iter()
        .map(|job| job.target_id.clone())
        .collect();
    let resumed = process_recovery_jobs(
        scope,
        &pool,
        &mut fs,
        &build_registry(),
        &mut RecoverySession::default(),
        Some(&selected),
        None,
        None,
    )
    .await?;
    assert_eq!(resumed.unresolved_count(), 0);
    assert_eq!(count(&pool, "artifact_objects").await, 12);
    Ok(())
}

#[cfg(feature = "sqlcipher")]
#[tokio::test]
async fn unsupported_dpapi_protection_is_reported_before_requesting_a_password() -> Result<()> {
    let root = tempfile::tempdir()?;
    windows(root.path(), false).await?;
    let v = vectors();
    let master = root
        .path()
        .join("Users/alice/AppData/Roaming/Microsoft/Protect")
        .join(v["windows_sid"].as_str().unwrap())
        .join(v["master_key_guid"].as_str().unwrap());
    let mut bytes = std::fs::read(&master)?;
    bytes[156..160].copy_from_slice(&0x1234u32.to_le_bytes());
    std::fs::write(master, bytes)?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let report = process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
    assert_eq!(report.jobs[0].status, RecoveryStatus::Unsupported);
    assert!(report.requests().is_empty());
    Ok(())
}

#[cfg(feature = "sqlcipher")]
#[tokio::test]
async fn keychain_selector_misses_are_store_scoped_before_password_input() -> Result<()> {
    let root = tempfile::tempdir()?;
    macos(root.path(), false, false).await?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let mut session = RecoverySession::default();
    let mut report = process(&pool, scope, &mut fs, &mut session).await?;
    let job = &mut report.jobs[0];
    job.credentials.clear();
    let error = crate::recovery::providers::keychain::recover(
        PreparationContext {
            pool: &pool,
            filesystem: &mut fs,
            session: &session,
            job,
            cancel: None,
        },
        crate::recovery::providers::keychain::Selection {
            home: "/Users/alice",
            service: b"Different application service",
            account: b"Different account",
        },
    )
    .await
    .unwrap_err();
    let failure = error.downcast_ref::<PreparationFailure>().unwrap();
    assert_eq!(failure.status, RecoveryStatus::MissingEvidence);
    assert_eq!(failure.reason, "keychain_item_missing");
    assert!(job.credentials.is_empty());
    Ok(())
}
