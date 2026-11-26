use super::*;

fn values() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/linux-values.json")).unwrap()
}

#[tokio::test]
async fn unsafe_or_unsupported_store_settings_do_not_escape_the_user_or_prompt() -> Result<()> {
    for (backend, contents, expected) in [
        (
            "gnome_libsecret",
            b"../bob".as_slice(),
            RecoveryStatus::Malformed,
        ),
        (
            "gnome_libsecret",
            b"work/keyring".as_slice(),
            RecoveryStatus::Malformed,
        ),
        ("gnome_libsecret", b"".as_slice(), RecoveryStatus::Malformed),
        (
            "kwallet6",
            b"[Wallet]\nDefault Wallet[$e]=$HOME/other\n".as_slice(),
            RecoveryStatus::Unsupported,
        ),
        (
            "kwallet6",
            b"[Wallet][$i]\nDefault Wallet=other\n".as_slice(),
            RecoveryStatus::Unsupported,
        ),
        (
            "kwallet6",
            b"[Wallet]\nDefault Wallet=a\nDefault Wallet=b\n".as_slice(),
            RecoveryStatus::Malformed,
        ),
    ] {
        let root = tempfile::tempdir()?;
        profile(
            root.path(),
            "home/alice",
            "Signal",
            Some(backend),
            "v11_config",
        )
        .await?;
        if backend == "gnome_libsecret" {
            gnome(root.path(), "home/alice", false, false)?;
            std::fs::write(
                root.path().join("home/alice/.local/share/keyrings/default"),
                contents,
            )?;
        } else {
            wallet(root.path(), "home/alice", "kdewallet")?;
            std::fs::write(root.path().join("home/alice/.config/kwalletrc"), contents)?;
        }
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        let result = process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
        assert_eq!(result.jobs[0].status, expected);
        assert!(result.requests().is_empty());
        assert!(result.jobs[0]
            .sources
            .iter()
            .all(|s| !s.path.contains("/bob/")));
    }
    Ok(())
}
async fn profile(
    root: &Path,
    home: &str,
    name: &str,
    backend: Option<&str>,
    field: &str,
) -> Result<std::path::PathBuf> {
    let path = root.join(home).join(".config").join(name);
    database(&path.join("sql/db.sqlite"), true, false).await?;
    let mut config = values()[field].clone();
    config.as_object_mut().unwrap().remove("safeStorageBackend");
    if let Some(backend) = backend {
        config["safeStorageBackend"] = backend.into();
    }
    std::fs::write(path.join("config.json"), serde_json::to_vec(&config)?)?;
    Ok(path)
}
fn gnome(root: &Path, home: &str, beta: bool, ambiguous: bool) -> Result<()> {
    let directory = root.join(home).join(".local/share/keyrings");
    std::fs::create_dir_all(&directory)?;
    let bytes = match (beta, ambiguous) {
        (_, true) => include_bytes!("../fixtures/linux-gnome-ambiguous.keyring").as_slice(),
        (true, false) => include_bytes!("../fixtures/linux-gnome-beta.keyring").as_slice(),
        (false, false) => include_bytes!("../fixtures/linux-gnome.keyring").as_slice(),
    };
    std::fs::write(directory.join("login.keyring"), bytes)?;
    Ok(())
}
fn wallet(root: &Path, home: &str, name: &str) -> Result<()> {
    let directory = root.join(home).join(".local/share/kwalletd");
    std::fs::create_dir_all(&directory)?;
    std::fs::write(
        directory.join(format!("{name}.kwl")),
        include_bytes!("../fixtures/linux-wallet.kwl"),
    )?;
    std::fs::write(
        directory.join(format!("{name}.salt")),
        include_bytes!("../fixtures/linux-wallet.salt"),
    )?;
    Ok(())
}
fn supply(session: &mut RecoverySession, request: &CredentialRequest) -> Result<()> {
    session.provide_password(
        &request.id,
        ParserSecret::new(values()["password"].as_str().unwrap().as_bytes().to_vec()),
    )
}
async fn objects(pool: &SqlitePool) -> Result<Vec<serde_json::Value>> {
    let rows: Vec<String> = sqlx::query_scalar("SELECT json FROM artifact_objects ORDER BY id")
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(|s| Ok(serde_json::from_str(&s)?))
        .collect()
}

#[tokio::test]
async fn config_keys_and_v10_need_no_store_credentials() -> Result<()> {
    for (field, method) in [
        ("legacy_config", "plaintext_config_key"),
        ("v10_config", "linux_v10_legacy_obfuscation"),
    ] {
        let root = tempfile::tempdir()?;
        profile(
            root.path(),
            "home/alice",
            "Signal Beta AppImage",
            None,
            field,
        )
        .await?;
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        let result = process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
        assert_eq!(result.jobs.len(), 1);
        assert_eq!(result.jobs[0].platform, RecoveryPlatform::Linux);
        assert_eq!(result.jobs[0].status, RecoveryStatus::Complete);
        assert_eq!(result.jobs[0].method.as_deref(), Some(method));
        assert!(result.requests().is_empty());
        assert!(result.jobs[0].credentials.is_empty());
        assert_eq!(count(&pool, "artifact_objects").await, 6);
    }
    Ok(())
}

#[tokio::test]
async fn protected_stores_retry_after_restart_preserve_provenance_and_publication() -> Result<()> {
    for (backend, name, role, authentication) in [
        (
            "gnome_libsecret",
            "Signal",
            "gnome_keyring",
            "gnome_keyring_unkeyed_md5_checksum",
        ),
        (
            "gnome_libsecret",
            "Signal Beta AppImage",
            "gnome_keyring",
            "gnome_keyring_unkeyed_md5_checksum",
        ),
        (
            "kwallet6",
            "Signal Beta AppImage",
            "kwallet",
            "kwallet_encrypted_unkeyed_checksum",
        ),
        (
            "kwallet5",
            "Signal",
            "kwallet",
            "kwallet_encrypted_unkeyed_checksum",
        ),
    ] {
        let root = tempfile::tempdir()?;
        profile(root.path(), "home/alice", name, Some(backend), "v11_config").await?;
        if backend == "gnome_libsecret" {
            gnome(root.path(), "home/alice", name.contains("Beta"), false)?;
        } else {
            wallet(root.path(), "home/alice", "kdewallet")?;
        }
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        let pending = process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
        assert_eq!(pending.jobs[0].status, RecoveryStatus::NeedsInput);
        assert_eq!(count(&pool, "artifact_objects").await, 0);
        let reloaded = load_recovery_jobs(&pool, scope).await?;
        let request = reloaded.requests().remove(0);
        assert_eq!(request.id, pending.requests()[0].id);
        let mut session = RecoverySession::default();
        session.provide_password(
            &request.id,
            ParserSecret::new(b"SYNTHETIC-WRONG-PASSWORD".to_vec()),
        )?;
        let failed = process(&pool, scope, &mut fs, &mut session).await?;
        assert_eq!(failed.jobs[0].status, RecoveryStatus::AuthenticationFailed);
        assert_eq!(count(&pool, "artifact_objects").await, 0);
        supply(&mut session, &request)?;
        let parsed = process(&pool, scope, &mut fs, &mut session).await?;
        assert_eq!(parsed.jobs[0].status, RecoveryStatus::Complete);
        assert_eq!(
            parsed.jobs[0].method.as_deref(),
            Some(if role == "gnome_keyring" {
                "gnome_keyring_password"
            } else {
                "kwallet_password"
            }),
        );
        assert_eq!(
            parsed.jobs[0].store_validation.as_deref(),
            Some(authentication)
        );
        assert_eq!(
            parsed.jobs[0].output_validation.as_deref(),
            Some("sqlcipher_schema_and_parsed_pages")
        );
        let source = parsed.jobs[0]
            .sources
            .iter()
            .find(|s| s.role == role)
            .unwrap();
        assert!(source.sha256.is_some());
        assert_eq!(source.record_offsets.len(), 1);
        assert!(source.record_offsets[0] > 0);
        let rows = objects(&pool).await?;
        assert_eq!(rows.len(), 6);
        assert!(rows
            .iter()
            .any(|row| row["body"] == "BEGIN SYNTHETIC SIGNAL RECOVERY"));
        let published = parsed.jobs[0].published_attempt_id;
        session.provide_password(
            &request.id,
            ParserSecret::new(b"SYNTHETIC-WRONG-PASSWORD".to_vec()),
        )?;
        let failed = process(&pool, scope, &mut fs, &mut session).await?;
        assert_eq!(failed.jobs[0].published_attempt_id, published);
        assert_eq!(objects(&pool).await?, rows);
        let serialized = serde_json::to_string(&failed)?;
        for secret in [
            "SYNTHETIC-WRONG-PASSWORD",
            "SYNTHETIC-GNOME-PASSWORD",
            "SYNTHETIC+Safe/Storage",
            values()["database_key"].as_str().unwrap(),
        ] {
            assert!(!serialized.contains(secret));
        }
    }
    Ok(())
}

#[tokio::test]
async fn shared_store_prompts_once_and_other_accounts_stay_pending() -> Result<()> {
    let root = tempfile::tempdir()?;
    for (home, name) in [
        ("home/alice", "Signal"),
        ("home/alice", "Signal Beta AppImage"),
        ("home/bob", "Signal"),
    ] {
        profile(root.path(), home, name, Some("kwallet6"), "v11_config").await?;
        wallet(root.path(), home, "kdewallet")?;
    }
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let mut session = RecoverySession::default();
    let pending = process(&pool, scope, &mut fs, &mut session).await?;
    let requests = pending.requests();
    assert_eq!(requests.len(), 2);
    let alice = requests.iter().find(|r| r.targets.len() == 2).unwrap();
    supply(&mut session, alice)?;
    let parsed = process_recovery_jobs(
        scope,
        &pool,
        &mut fs,
        &build_registry(),
        &mut session,
        Some(&alice.targets),
        None,
        None,
    )
    .await?;
    assert_eq!(parsed.jobs.len(), 2);
    assert!(parsed
        .jobs
        .iter()
        .all(|j| j.status == RecoveryStatus::Complete));
    assert_eq!(count(&pool, "artifact_objects").await, 12);
    let all = load_recovery_jobs(&pool, scope).await?;
    assert_eq!(all.unresolved_count(), 1);
    assert_ne!(all.requests()[0].id, alice.id);
    assert!(all
        .jobs
        .iter()
        .filter(|j| j.status == RecoveryStatus::Complete)
        .all(|j| j.sources.iter().all(|s| !s.path.contains("/bob/"))));
    Ok(())
}

#[tokio::test]
async fn missing_or_unsupported_inputs_never_request_a_password() -> Result<()> {
    for scenario in [
        "salt_missing",
        "salt_short",
        "salt_large",
        "gpg",
        "gnome_plaintext",
        "unknown_backend",
    ] {
        let root = tempfile::tempdir()?;
        let backend = if scenario.starts_with("gnome") {
            "gnome_libsecret"
        } else if scenario == "unknown_backend" {
            "unknown"
        } else {
            "kwallet6"
        };
        profile(
            root.path(),
            "home/alice",
            "Signal",
            Some(backend),
            "v11_config",
        )
        .await?;
        wallet(root.path(), "home/alice", "kdewallet")?;
        gnome(root.path(), "home/alice", false, false)?;
        let store = root.path().join("home/alice/.local/share/kwalletd");
        match scenario {
            "salt_missing" => std::fs::remove_file(store.join("kdewallet.salt"))?,
            "salt_short" => std::fs::write(store.join("kdewallet.salt"), [0; 55])?,
            "salt_large" => std::fs::write(store.join("kdewallet.salt"), [0; 57])?,
            "gpg" => {
                let path = store.join("kdewallet.kwl");
                let mut bytes = std::fs::read(&path)?;
                bytes[14] = 2;
                std::fs::write(path, bytes)?;
            }
            "gnome_plaintext" => std::fs::write(
                root.path()
                    .join("home/alice/.local/share/keyrings/login.keyring"),
                b"[keyring]\ndisplay-name=unsupported plaintext collection\n",
            )?,
            _ => {}
        }
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        let result = process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
        let expected = match scenario {
            "salt_missing" => RecoveryStatus::MissingEvidence,
            "salt_short" => RecoveryStatus::Malformed,
            "salt_large" => RecoveryStatus::LimitExceeded,
            _ => RecoveryStatus::Unsupported,
        };
        assert_eq!(result.jobs[0].status, expected, "{scenario}");
        assert!(result.requests().is_empty());
        assert_eq!(count(&pool, "artifact_objects").await, 0);
    }
    Ok(())
}

#[tokio::test]
async fn backend_absence_requires_a_unique_store_and_supplied_key_can_resolve_it() -> Result<()> {
    let root = tempfile::tempdir()?;
    profile(root.path(), "home/alice", "Signal", None, "v11_config").await?;
    gnome(root.path(), "home/alice", false, false)?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let one = process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
    assert_eq!(one.jobs[0].status, RecoveryStatus::NeedsInput);
    wallet(root.path(), "home/alice", "kdewallet")?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let mut session = RecoverySession::default();
    let ambiguous = process(&pool, scope, &mut fs, &mut session).await?;
    assert_eq!(ambiguous.jobs[0].reason, "linux_key_store_ambiguous");
    assert!(ambiguous.requests().is_empty());
    session.provide_secret(
        &ambiguous.jobs[0].target_id,
        "database_key",
        ParserSecret::new(
            values()["database_key"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
    )?;
    let supplied = process(&pool, scope, &mut fs, &mut session).await?;
    assert_eq!(supplied.jobs[0].status, RecoveryStatus::Complete);
    assert_eq!(
        supplied.jobs[0].method.as_deref(),
        Some("provided_database_key")
    );
    Ok(())
}

#[tokio::test]
async fn gnome_selection_rejects_ambiguity_and_a_different_release() -> Result<()> {
    for (name, ambiguous, reason) in [
        ("Signal", true, "credential_gnome_keyring_item_ambiguous"),
        (
            "Signal Beta",
            false,
            "credential_gnome_keyring_item_missing",
        ),
    ] {
        let root = tempfile::tempdir()?;
        profile(
            root.path(),
            "home/alice",
            name,
            Some("gnome_libsecret"),
            "v11_config",
        )
        .await?;
        gnome(root.path(), "home/alice", false, ambiguous)?;
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        let mut session = RecoverySession::default();
        let pending = process(&pool, scope, &mut fs, &mut session).await?;
        supply(&mut session, &pending.requests()[0])?;
        let result = process(&pool, scope, &mut fs, &mut session).await?;
        assert_eq!(result.jobs[0].status, RecoveryStatus::MissingEvidence);
        assert_eq!(result.jobs[0].reason, reason);
        assert_eq!(count(&pool, "artifact_objects").await, 0);
    }
    Ok(())
}

#[tokio::test]
async fn default_collections_and_encoded_wallet_names_remain_account_scoped() -> Result<()> {
    for backend in ["gnome_libsecret", "kwallet6"] {
        let root = tempfile::tempdir()?;
        profile(
            root.path(),
            "home/alice",
            "Signal",
            Some(backend),
            "v11_config",
        )
        .await?;
        if backend == "gnome_libsecret" {
            gnome(root.path(), "home/alice", false, false)?;
            let dir = root.path().join("home/alice/.local/share/keyrings");
            std::fs::rename(dir.join("login.keyring"), dir.join("research.keyring"))?;
            std::fs::write(dir.join("default"), b"research\n")?;
        } else {
            wallet(root.path(), "home/alice", "Research;2FWallet")?;
            std::fs::write(
                root.path().join("home/alice/.config/kwalletrc"),
                b"[Wallet]\nDefault Wallet=Research/Wallet\n",
            )?;
        }
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        let mut session = RecoverySession::default();
        let pending = process(&pool, scope, &mut fs, &mut session).await?;
        assert_eq!(pending.jobs[0].status, RecoveryStatus::NeedsInput);
        supply(&mut session, &pending.requests()[0])?;
        let parsed = process(&pool, scope, &mut fs, &mut session).await?;
        assert_eq!(parsed.jobs[0].status, RecoveryStatus::Complete);
        assert!(parsed.jobs[0].sources.iter().any(
            |s| s.path.contains("research.keyring") || s.path.contains("Research;2FWallet.kwl")
        ));
    }
    Ok(())
}

#[tokio::test]
async fn settings_timer_events_and_surviving_previews_are_published_with_provenance() -> Result<()>
{
    let root = tempfile::tempdir()?;
    let path = profile(
        root.path(),
        "home/alice",
        "Signal Beta AppImage",
        Some("kwallet6"),
        "v11_config",
    )
    .await?;
    wallet(root.path(), "home/alice", "kdewallet")?;
    let mut conn = SqliteConnection::connect_with(
        &SqliteConnectOptions::new().filename(path.join("sql/db.sqlite")),
    )
    .await?;
    sqlx::raw_sql(&format!(
        "PRAGMA key=\"x'{}'\";",
        vectors()["database_key"].as_str().unwrap()
    ))
    .execute(&mut conn)
    .await?;
    sqlx::raw_sql("UPDATE conversations SET json=json_set(json,'$.expireTimer',30,'$.expireTimerVersion',3,'$.lastMessage','SYNTHETIC expired preview') WHERE id='peer';
        INSERT INTO messages(id,type,conversationId,json,sent_at) VALUES('timer','timer-notification','peer','{\"flags\":2,\"expirationTimerUpdate\":{\"expireTimer\":30}}',1700000003000);")
        .execute(&mut conn).await?;
    conn.close().await?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let mut session = RecoverySession::default();
    let pending = process(&pool, scope, &mut fs, &mut session).await?;
    supply(&mut session, &pending.requests()[0])?;
    let parsed = process(&pool, scope, &mut fs, &mut session).await?;
    assert_eq!(parsed.jobs[0].status, RecoveryStatus::Complete);
    let rows = objects(&pool).await?;
    let chat = rows
        .iter()
        .find(|r| r["record_type"] == "chat" && r["chat"]["id"] == "peer")
        .unwrap();
    assert_eq!(
        chat["chat"]["disappearing_messages"]["expire_timer_seconds"],
        30
    );
    assert_eq!(
        chat["chat"]["last_message_cache"]["text"],
        "SYNTHETIC expired preview"
    );
    assert_eq!(chat["source"]["table"], "conversations");
    assert!(rows
        .iter()
        .any(|r| r["record_type"] == "expiration_timer_update" && r["source"]["id"] == "timer"));
    let timers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM timeline_events WHERE event_type='signal.expiration_timer_update'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(timers, 1);
    assert!(!rows
        .iter()
        .any(|r| r["record_type"] == "message" && r["body"] == "SYNTHETIC expired preview"));
    Ok(())
}

#[tokio::test]
async fn shared_gnome_selectors_reject_broad_matches_and_deduplicate_overlaps() -> Result<()> {
    for beta in [false, true] {
        let root = tempfile::tempdir()?;
        profile(
            root.path(),
            "home/alice",
            if beta { "Signal Beta" } else { "Signal" },
            Some("gnome_libsecret"),
            "v11_config",
        )
        .await?;
        gnome(root.path(), "home/alice", beta, false)?;
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        let mut session = RecoverySession::default();
        let mut pending = process(&pool, scope, &mut fs, &mut session).await?;
        supply(&mut session, &pending.requests()[0])?;
        let job = &mut pending.jobs[0];
        // Select by schema alone, without an application attribute. The stable
        // fixture has two matching items; the beta fixture has exactly one.
        let selector = &[("xdg:schema", "chrome_libsecret_os_crypt_password_v2")][..];
        let result = crate::recovery::providers::linux::recover_gnome(
            PreparationContext {
                pool: &pool,
                filesystem: &mut fs,
                session: &session,
                job,
                cancel: None,
            },
            "/home/alice",
            &[selector, selector],
        )
        .await;
        if !beta {
            let error = result.unwrap_err();
            let failure = error.downcast_ref::<PreparationFailure>().unwrap();
            assert_eq!(failure.status, RecoveryStatus::MissingEvidence);
            assert_eq!(failure.reason, "credential_gnome_keyring_item_ambiguous");
            continue;
        }
        let recovered = result?;
        assert_eq!(
            recovered.expose(),
            values()["safe_storage"].as_str().unwrap().as_bytes()
        );
        assert_eq!(job.method.as_deref(), Some("gnome_keyring_password"));
        assert_eq!(job.credentials.len(), 1);
        assert!(!job.credentials[0].needed);
        let source = job
            .sources
            .iter()
            .find(|source| source.role == "gnome_keyring")
            .unwrap();
        assert!(source.sha256.is_some());
        assert_eq!(source.record_offsets.len(), 1);
    }
    Ok(())
}
