//! Offline account-scoped Keychain input resolution and secret selection.
use super::*;
use exhume_artefacts::formats::keychain::{KeychainError, LegacyKeychain};
use zeroize::Zeroizing;
pub(crate) struct Selection<'a> {
    pub home: &'a str,
    pub service: &'a [u8],
    pub account: &'a [u8],
}
pub(crate) async fn recover<F: Filesystem>(
    context: PreparationContext<'_, F>,
    selection: Selection<'_>,
) -> Result<ParserSecret>
where
    F::FileType: FileCommon,
{
    let PreparationContext {
        pool,
        filesystem: fs,
        session,
        job,
        cancel,
    } = context;
    let Selection {
        home,
        service,
        account,
    } = selection;
    let mut path = format!("{home}/Library/Keychains/login.keychain-db");
    let mut keychain = read_dependency(
        pool,
        fs,
        job,
        &path,
        "login_keychain",
        64 * 1024 * 1024,
        cancel,
    )
    .await?;
    if keychain.is_none() {
        path = format!("{home}/Library/Keychains/login.keychain");
        keychain = read_dependency(
            pool,
            fs,
            job,
            &path,
            "login_keychain",
            64 * 1024 * 1024,
            cancel,
        )
        .await?;
    }
    let bytes = keychain
        .ok_or_else(|| blocked(RecoveryStatus::MissingEvidence, "login_keychain_missing"))?;
    let parsed = LegacyKeychain::parse(&bytes).map_err(map_keychain_error)?;
    parsed
        .check_password_protection()
        .map_err(map_keychain_error)?;
    let matching = parsed
        .generic_passwords()
        .map_err(map_keychain_error)?
        .iter()
        .filter(|item| item.service() == Some(service) && item.account() == Some(account))
        .count();
    if matching != 1 {
        return Err(blocked(
            RecoveryStatus::MissingEvidence,
            if matching == 0 {
                "keychain_item_missing"
            } else {
                "keychain_item_ambiguous"
            },
        ));
    }
    let salt = parsed
        .protected_entropy_identifier()
        .ok_or_else(|| blocked(RecoveryStatus::Malformed, "keychain_database_blob_missing"))?;
    let root = home
        .rsplit_once("/Users/")
        .map(|(root, _)| root)
        .ok_or_else(|| blocked(RecoveryStatus::Unsupported, "macos_user_scope_unknown"))?;
    let entropy_directory = format!("{root}/private/var/db/SystemKeys/");
    // The salt is a hexadecimal identifier. Native SystemKeys filenames use
    // uppercase hex, whereas the format API returns lowercase. Match only the
    // filename without case, preserving the exact acquired volume/directory.
    let candidates = sqlx::query("SELECT id,identifier,absolute_path,size FROM system_files WHERE evidence_id=? AND partition_id=? AND is_dir=0 AND lower(name)=lower(?) AND absolute_path=? || name ORDER BY id LIMIT 2")
        .bind(job.scope.evidence_id)
        .bind(job.scope.partition_id)
        .bind(&salt)
        .bind(&entropy_directory)
        .fetch_all(pool)
        .await?;
    if candidates.len() > 1 {
        return Err(blocked(
            RecoveryStatus::MissingEvidence,
            "systemkeys_companion_ambiguous",
        ));
    }
    let entropy_source = candidates
        .first()
        .map(|row| source_row(row, "protected_entropy"))
        .transpose()?;
    let entropy_path = entropy_source.as_ref().map_or_else(
        || format!("{entropy_directory}{salt}"),
        |source| source.path.clone(),
    );
    // Inventory the optional companion before requesting input. Its bytes are
    // needed only if direct password authentication fails.
    if let Some(source) = entropy_source {
        job.sources.push(source);
    }
    let id = scoped_id("recovery-store-", job.scope, job.inventory_run_id, &path);
    let password = session.password(job, id, format!("Keychain password for {home:?}"))?;
    let unlocked = match blocking(|| parsed.unlock_password(password.expose(), cancel)) {
        Ok(unlocked) => {
            job.method = Some("keychain_direct_password".into());
            unlocked
        }
        Err(KeychainError::AuthenticationFailed) => {
            let data = read_dependency(
                pool,
                fs,
                job,
                &entropy_path,
                "protected_entropy",
                1024 * 1024,
                cancel,
            )
            .await?
            .ok_or_else(|| {
                blocked(
                    RecoveryStatus::MissingEvidence,
                    "direct_authentication_failed_systemkeys_companion_missing",
                )
            })?;
            let value =
                plist::Value::from_reader(std::io::Cursor::new(data.as_slice())).map_err(|_| {
                    blocked(RecoveryStatus::Malformed, "protected_entropy_plist_invalid")
                })?;
            let plist::Value::Data(data) = value else {
                return Err(blocked(
                    RecoveryStatus::Malformed,
                    "protected_entropy_requires_cfdata",
                ));
            };
            let data = Zeroizing::new(data);
            let entropy: &[u8; 32] = data.as_slice().try_into().map_err(|_| {
                blocked(
                    RecoveryStatus::Malformed,
                    "protected_entropy_requires_32_bytes",
                )
            })?;
            let unlocked = blocking(|| {
                LegacyKeychain::parse(&bytes)?.unlock_login_password(
                    password.expose(),
                    entropy,
                    cancel,
                )
            })
            .map_err(map_keychain_error)?;
            job.method = Some("keychain_login_password_protected_entropy".into());
            unlocked
        }
        Err(error) => return Err(map_keychain_error(error)),
    };
    job.store_validation = Some("keychain_database_blob".into());
    let storage = unlocked
        .recover_generic_password(service, account, cancel)
        .map_err(map_keychain_error)?;
    if let Some(source) = job.sources.iter_mut().find(|s| s.role == "login_keychain") {
        source.record_offsets = vec![
            u64::try_from(storage.record_offset())?,
            u64::try_from(storage.wrapping_key_record_offset())?,
        ];
    }
    Ok(ParserSecret::new(storage.expose().to_vec()))
}
fn map_keychain_error(error: KeychainError) -> anyhow::Error {
    use KeychainError::*;
    match error {
        AuthenticationFailed => blocked(
            RecoveryStatus::AuthenticationFailed,
            "keychain_authentication_failed",
        ),
        Cancelled => blocked(RecoveryStatus::Cancelled, "cancelled"),
        UnsupportedFormat | UnsupportedVersion { .. } | UnsupportedProtection => blocked(
            RecoveryStatus::Unsupported,
            "keychain_protection_unsupported",
        ),
        ItemNotFound | MissingWrappingKey => blocked(
            RecoveryStatus::MissingEvidence,
            "keychain_item_or_wrapping_key_missing",
        ),
        AmbiguousItem | AmbiguousWrappingKey => blocked(
            RecoveryStatus::MissingEvidence,
            "keychain_item_or_wrapping_key_ambiguous",
        ),
        LimitExceeded { .. } => blocked(RecoveryStatus::LimitExceeded, "keychain_limit"),
        InvalidPayload => blocked(
            RecoveryStatus::ValidationFailed,
            "keychain_payload_validation_failed",
        ),
        _ => blocked(RecoveryStatus::Malformed, "keychain_malformed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_and_wrapping_key_failures_use_store_diagnostics() {
        for (error, reason) in [
            (
                KeychainError::ItemNotFound,
                "keychain_item_or_wrapping_key_missing",
            ),
            (
                KeychainError::MissingWrappingKey,
                "keychain_item_or_wrapping_key_missing",
            ),
            (
                KeychainError::AmbiguousItem,
                "keychain_item_or_wrapping_key_ambiguous",
            ),
            (
                KeychainError::AmbiguousWrappingKey,
                "keychain_item_or_wrapping_key_ambiguous",
            ),
        ] {
            let error = map_keychain_error(error);
            let failure = error.downcast_ref::<PreparationFailure>().unwrap();
            assert_eq!(failure.status, RecoveryStatus::MissingEvidence);
            assert_eq!(failure.reason, reason);
        }
    }
}
