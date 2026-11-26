use std::process::Command;

#[test]
fn help_exposes_generic_recovery_inputs_separately_from_container_passwords() {
    let output = Command::new(env!("CARGO_BIN_EXE_exhume_indexer"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for option in [
        "--retry-recovery",
        "--recovery-target",
        "--credential-file",
        "--recovery-secret-file",
        "--recovery-option",
        "--no-recovery-input",
        "--password-file",
    ] {
        assert!(help.contains(option));
    }
}

#[cfg(feature = "sqlcipher")]
mod encrypted {
    use super::*;
    use anyhow::Result;
    use serde_json::Value;
    use sqlx::{
        sqlite::{SqliteConnectOptions, SqliteConnection},
        Connection,
    };
    use std::path::Path;

    #[tokio::test]
    async fn linux_wallet_cli_resumes_the_same_inventory_without_changing_inputs() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("source");
        let profile = root.join("home/alice/.config/Signal Beta AppImage");
        std::fs::create_dir_all(profile.join("sql"))?;
        let database_file = profile.join("sql/db.sqlite");
        let mut connection = SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .filename(&database_file)
                .create_if_missing(true),
        )
        .await?;
        sqlx::raw_sql(&format!(
            "PRAGMA key=\"x'{}'\"; PRAGMA cipher_compatibility=4;",
            values()["database_key"].as_str().unwrap()
        ))
        .execute(&mut connection)
        .await?;
        sqlx::raw_sql(include_str!("../src/recovery/fixtures/schema.sql"))
            .execute(&mut connection)
            .await?;
        connection.close().await?;
        let linux: Value =
            serde_json::from_str(include_str!("../src/recovery/fixtures/linux-values.json"))?;
        let mut config = linux["v11_config"].clone();
        config["safeStorageBackend"] = "kwallet6".into();
        std::fs::write(profile.join("config.json"), serde_json::to_vec(&config)?)?;
        let directory = root.join("home/alice/.local/share/kwalletd");
        std::fs::create_dir_all(&directory)?;
        std::fs::write(
            directory.join("kdewallet.kwl"),
            include_bytes!("../src/recovery/fixtures/linux-wallet.kwl"),
        )?;
        std::fs::write(
            directory.join("kdewallet.salt"),
            include_bytes!("../src/recovery/fixtures/linux-wallet.salt"),
        )?;
        let before = std::fs::read(&database_file)?;
        let index = temp.path().join("index.sqlite");
        let (output, pending) = run(&root, &index, &["--extract-artefacts"])?;
        assert_eq!(output.status.code(), Some(2));
        let job = &pending["recovery"]["jobs"][0];
        assert_eq!(job["platform"], "linux");
        assert_eq!(job["status"], "needs_input");
        let password = temp.path().join("password.bin");
        std::fs::write(&password, linux["password"].as_str().unwrap())?;
        let mapping = format!(
            "{}={}",
            job["credentials"][0]["id"].as_str().unwrap(),
            password.display()
        );
        let partition = pending["partition_id"].as_i64().unwrap().to_string();
        let (output, retried) = run(
            &root,
            &index,
            &[
                "--retry-recovery",
                "--partition-id",
                &partition,
                "--credential-file",
                &mapping,
            ],
        )?;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(retried["run_id"], pending["run_id"]);
        assert_eq!(retried["indexed_paths"], pending["indexed_paths"]);
        assert_eq!(retried["recovery_issues"], 0);
        assert_eq!(retried["recovery"]["jobs"][0]["method"], "kwallet_password");
        assert_eq!(retried["recovery"]["jobs"][0]["status"], "complete");
        assert_eq!(std::fs::read(&database_file)?, before);
        assert_eq!(
            std::fs::read(directory.join("kdewallet.kwl"))?,
            include_bytes!("../src/recovery/fixtures/linux-wallet.kwl")
        );
        assert_eq!(
            std::fs::read(directory.join("kdewallet.salt"))?,
            include_bytes!("../src/recovery/fixtures/linux-wallet.salt")
        );
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for secret in [
            "SYNTHETIC-GNOME-PASSWORD",
            "SYNTHETIC+Safe/Storage",
            linux["database_key"].as_str().unwrap(),
        ] {
            assert!(!text.contains(secret));
        }
        Ok(())
    }

    fn values() -> Value {
        serde_json::from_str(include_str!("../src/recovery/fixtures/signal-keys.json")).unwrap()
    }
    async fn fixture(root: &Path) -> Result<()> {
        let v = values();
        let home = root.join("Users/alice/AppData/Roaming");
        let directory = home.join("Signal/sql");
        std::fs::create_dir_all(&directory)?;
        let mut connection = SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .filename(directory.join("db.sqlite"))
                .create_if_missing(true),
        )
        .await?;
        sqlx::raw_sql(&format!(
            "PRAGMA key=\"x'{}'\"; PRAGMA cipher_compatibility=4;",
            v["database_key"].as_str().unwrap()
        ))
        .execute(&mut connection)
        .await?;
        sqlx::raw_sql(include_str!("../src/recovery/fixtures/schema.sql"))
            .execute(&mut connection)
            .await?;
        connection.close().await?;
        std::fs::write(
            home.join("Signal/config.json"),
            serde_json::to_vec(&v["windows_config"])?,
        )?;
        std::fs::write(
            home.join("Signal/Local State"),
            serde_json::to_vec(&v["windows_local_state"])?,
        )?;
        let protect = home
            .join("Microsoft/Protect")
            .join(v["windows_sid"].as_str().unwrap());
        std::fs::create_dir_all(&protect)?;
        std::fs::write(
            protect.join(v["master_key_guid"].as_str().unwrap()),
            hex::decode(v["master_key_file"].as_str().unwrap())?,
        )?;
        Ok(())
    }
    fn run(
        source: &Path,
        index: &Path,
        arguments: &[&str],
    ) -> Result<(std::process::Output, Value)> {
        let output = Command::new(env!("CARGO_BIN_EXE_exhume_indexer"))
            .args([
                "--body",
                source.to_str().unwrap(),
                "--database",
                index.to_str().unwrap(),
                "--json-report",
                "--no-progress",
                "--no-recovery-input",
            ])
            .args(arguments)
            .output()?;
        let json = serde_json::from_slice(&output.stdout).map_err(|e| {
            anyhow::anyhow!(
                "invalid CLI JSON: {e}; stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        })?;
        Ok((output, json))
    }

    #[tokio::test]
    async fn credential_file_retry_reuses_inventory_and_never_echoes_secrets() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        fixture(&source).await?;
        let database = temp.path().join("index.sqlite");
        let encrypted = source.join("Users/alice/AppData/Roaming/Signal/sql/db.sqlite");
        let before = std::fs::read(&encrypted)?;
        let (initial_output, initial) = run(&source, &database, &["--extract-artefacts"])?;
        assert_eq!(initial_output.status.code(), Some(2));
        assert_eq!(initial["recovery_issues"], 1);
        assert_eq!(initial["recovery"]["jobs"][0]["status"], "needs_input");
        let credential = initial["recovery"]["jobs"][0]["credentials"][0]["id"]
            .as_str()
            .unwrap();
        let partition = initial["partition_id"].as_i64().unwrap().to_string();
        let password = temp.path().join("password");
        std::fs::write(&password, values()["windows_password"].as_str().unwrap())?;
        let mapping = format!("{credential}={}", password.display());
        let (retried_output, retried) = run(
            &source,
            &database,
            &[
                "--retry-recovery",
                "--partition-id",
                &partition,
                "--credential-file",
                &mapping,
            ],
        )?;
        assert_eq!(
            retried_output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&retried_output.stderr)
        );
        assert_eq!(retried["run_id"], initial["run_id"]);
        assert_eq!(retried["indexed_paths"], initial["indexed_paths"]);
        assert_eq!(retried["recovery_issues"], 0);
        assert_eq!(retried["recovery"]["jobs"][0]["status"], "complete");
        assert_eq!(std::fs::read(encrypted)?, before);
        for output in [&initial_output, &retried_output] {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            for name in ["windows_password", "database_key", "protected_entropy"] {
                assert!(!text.contains(values()[name].as_str().unwrap()));
            }
        }
        let mut connection =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&database))
                .await?;
        let runs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM index_runs")
            .fetch_one(&mut connection)
            .await?;
        let objects: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifact_objects WHERE parser='desktop_signal'",
        )
        .fetch_one(&mut connection)
        .await?;
        assert_eq!(runs, 1);
        assert_eq!(objects, 6);
        let master_keys: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifact_objects WHERE parser='windows_dpapi_masterkey'",
        )
        .fetch_one(&mut connection)
        .await?;
        assert_eq!(master_keys, 1);
        connection.close().await?;
        Ok(())
    }
}
