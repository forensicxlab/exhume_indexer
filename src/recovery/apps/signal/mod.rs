//! Signal locations, configuration envelopes and parser option preparation.
mod linux;
use crate::recovery::evidence::*;
use crate::recovery::*;
use exhume_artefacts::recovery::signal::{EnvelopeKind, SignalKeyEnvelope, SignalRecoveryError};
use exhume_filesystem::filesystem::FsFileReadSeek;
use std::io::Read;
pub(super) fn profile(path: &str) -> (String, RecoveryPlatform) {
    let normalized = path.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    let root = if lower.ends_with("/sql/db.sqlite") {
        normalized[..normalized.len() - 14].to_string()
    } else {
        normalized
            .rsplit_once('/')
            .map_or(String::new(), |(p, _)| p.into())
    };
    let lower = root.to_ascii_lowercase();
    let platform = if root.ends_with("/Library/Application Support/Signal") {
        RecoveryPlatform::Macos
    } else if lower.ends_with("/appdata/roaming/signal") {
        RecoveryPlatform::Windows
    } else if linux::owner(&root).is_some() {
        RecoveryPlatform::Linux
    } else {
        RecoveryPlatform::Unknown
    };
    (root, platform)
}

pub(super) async fn prepare<F>(context: PreparationContext<'_, F>) -> Result<PreparedParser>
where
    F: Filesystem + Send,
    F::FileType: FileCommon + Send,
{
    let PreparationContext {
        pool,
        filesystem: fs,
        session,
        job,
        cancel,
    } = context;
    match job.parameters.get("cipher_version") {
        None | Some(exhume_artefacts::ParserOptionValue::Integer(3 | 4)) => {}
        _ => {
            return Err(blocked(
                RecoveryStatus::Unsupported,
                "cipher_version_unsupported",
            ))
        }
    }
    let key = recover_key(pool, fs, session, job, cancel).await?;
    let mut options = ParserOptions::default();
    if session.secret(&job.target_id, "database_key").is_none() {
        if let Some(key) = key {
            options.insert_secret("database_key", key)?;
        }
    }
    let validation = if job.method.as_deref() == Some("plaintext_database") {
        "sqlite_schema_and_parsed_rows"
    } else {
        "sqlcipher_schema_and_parsed_pages"
    };
    Ok(PreparedParser {
        options,
        validation: validation.into(),
    })
}
pub(super) async fn recover_key<F: Filesystem>(
    pool: &SqlitePool,
    fs: &mut F,
    session: &RecoverySession,
    job: &mut RecoveryJob,
    cancel: Option<&AtomicBool>,
) -> Result<Option<ParserSecret>>
where
    F::FileType: FileCommon,
{
    let source = job
        .sources
        .first()
        .context("recovery primary source missing")?;
    if source.size_bytes < 16 {
        return Err(blocked(
            RecoveryStatus::Malformed,
            "database_header_truncated",
        ));
    }
    if source.size_bytes > session.limits.input_bytes {
        return Err(blocked(
            RecoveryStatus::LimitExceeded,
            "database_byte_limit",
        ));
    }
    let record = fs
        .get_file(source.fs_identifier)
        .or_else(|_| fs.get_file_by_path(&source.path, source.fs_identifier))
        .map_err(|_| blocked(RecoveryStatus::FileRead, "source_open_failed"))?;
    let mut reader = FsFileReadSeek::new(fs, record);
    let mut header = [0; 16];
    reader
        .read_exact(&mut header)
        .map_err(|_| blocked(RecoveryStatus::FileRead, "database_header_read_failed"))?;
    drop(reader);
    if &header == b"SQLite format 3\0" {
        job.method = Some("plaintext_database".into());
        return Ok(None);
    }
    // Even the smallest SQLite/SQLCipher page is 512 bytes. A fragment cannot
    // become readable by supplying a password or enabling the cipher backend.
    if source.size_bytes < 512 {
        return Err(blocked(
            RecoveryStatus::Malformed,
            "database_page_truncated",
        ));
    }
    if !cfg!(feature = "sqlcipher") {
        return Err(blocked(
            RecoveryStatus::BackendUnavailable,
            "sqlcipher_feature_required",
        ));
    }
    if let Some(key) = session.secret(&job.target_id, "database_key") {
        exhume_artefacts::formats::sqlite::sqlcipher::SqlCipherKey::from_hex(key.expose())
            .map_err(|_| blocked(RecoveryStatus::Malformed, "invalid_database_key"))?;
        job.method = Some("provided_database_key".into());
        return Ok(Some(ParserSecret::new(key.expose().to_vec())));
    }
    let path = format!("{}/config.json", job.root_path);
    let bytes = read_dependency(pool, fs, job, &path, "signal_config", 1024 * 1024, cancel)
        .await?
        .ok_or_else(|| blocked(RecoveryStatus::MissingEvidence, "signal_config_missing"))?;
    let config = SignalKeyEnvelope::parse(&bytes).map_err(map_signal_error)?;
    if let Some(key) = config.plaintext_key() {
        job.method = Some("plaintext_config_key".into());
        return Ok(Some(key));
    }
    if config.kind() == EnvelopeKind::Unsupported {
        return Err(blocked(
            RecoveryStatus::Unsupported,
            "key_envelope_unsupported",
        ));
    }
    let key = match job.platform {
        RecoveryPlatform::Macos => {
            let home = job
                .root_path
                .strip_suffix("/Library/Application Support/Signal")
                .ok_or_else(|| {
                    blocked(
                        RecoveryStatus::Unsupported,
                        "macos_profile_layout_unsupported",
                    )
                })?
                .to_owned();
            let storage = providers::keychain::recover(
                PreparationContext {
                    pool,
                    filesystem: fs,
                    session,
                    job,
                    cancel,
                },
                providers::keychain::Selection {
                    home: &home,
                    service: b"Signal Safe Storage",
                    account: b"Signal Key",
                },
            )
            .await?;
            config
                .recover_macos(storage.expose(), cancel)
                .map_err(map_signal_error)?
        }
        RecoveryPlatform::Windows => {
            let local = if config.kind() == EnvelopeKind::V10 {
                let path = format!("{}/Local State", job.root_path);
                read_dependency(pool, fs, job, &path, "local_state", 1024 * 1024, cancel).await?
            } else {
                None
            };
            let guid = config
                .windows_master_key_guid(local.as_deref().map(|v| v.as_slice()))
                .map_err(map_signal_error)?;
            let lower = job.root_path.to_ascii_lowercase();
            let marker = "/appdata/roaming/signal";
            ensure!(lower.ends_with(marker), "invalid Windows application root");
            let home = job.root_path[..job.root_path.len() - marker.len()].to_owned();
            let master = providers::dpapi::recover(
                PreparationContext {
                    pool,
                    filesystem: fs,
                    session,
                    job,
                    cancel,
                },
                providers::dpapi::Selection {
                    home: &home,
                    guid: &guid,
                },
            )
            .await?;
            let key = config
                .recover_windows(local.as_deref().map(|v| v.as_slice()), &master, cancel)
                .map_err(map_signal_error)?;
            job.store_validation = Some("dpapi_master_key_and_blob".into());
            key
        }
        RecoveryPlatform::Linux => {
            linux::recover_key(pool, fs, session, job, &config, &bytes, cancel).await?
        }
        RecoveryPlatform::Unknown => {
            return Err(blocked(
                RecoveryStatus::Unsupported,
                "profile_platform_unknown",
            ))
        }
    };
    Ok(Some(key))
}

pub(super) fn map_signal_error(error: SignalRecoveryError) -> anyhow::Error {
    use exhume_artefacts::formats::os_crypt::OsCryptError;
    match error {
        SignalRecoveryError::Dpapi(error) => providers::dpapi::map_error(error),
        SignalRecoveryError::MissingLocalState => blocked(
            RecoveryStatus::MissingEvidence,
            "signal_local_state_missing",
        ),
        SignalRecoveryError::UnsupportedEnvelope => {
            blocked(RecoveryStatus::Unsupported, "key_envelope_unsupported")
        }
        SignalRecoveryError::LimitExceeded => {
            blocked(RecoveryStatus::LimitExceeded, "config_byte_limit")
        }
        SignalRecoveryError::OsCrypt(OsCryptError::Cancelled) => {
            blocked(RecoveryStatus::Cancelled, "cancelled")
        }
        SignalRecoveryError::OsCrypt(_) | SignalRecoveryError::InvalidDatabaseKey => blocked(
            RecoveryStatus::ValidationFailed,
            "application_key_validation_failed",
        ),
        _ => blocked(RecoveryStatus::Malformed, "signal_config_malformed"),
    }
}
