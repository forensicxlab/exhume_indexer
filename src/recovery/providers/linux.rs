//! GNOME/KWallet account resolution and exact item selection.
use super::*;
use exhume_artefacts::formats::{
    gnome_keyring::{AttributeValue, Attributes, GnomeKeyring, KeyringError},
    kwallet::{KWallet, WalletError},
};
use std::collections::BTreeSet;
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SETTINGS_BYTES: u64 = 64 * 1024;
pub(crate) async fn gnome_path<F: Filesystem>(
    pool: &SqlitePool,
    fs: &mut F,
    job: &mut RecoveryJob,
    home: &str,
    cancel: Option<&AtomicBool>,
) -> Result<String>
where
    F::FileType: FileCommon,
{
    for directory in [
        format!("{home}/.local/share/keyrings"),
        format!("{home}/.gnome2/keyrings"),
    ] {
        if let Some(data) = read_dependency(
            pool,
            fs,
            job,
            &format!("{directory}/default"),
            "gnome_default_collection",
            MAX_SETTINGS_BYTES,
            cancel,
        )
        .await?
        {
            let name = std::str::from_utf8(&data)
                .map_err(|_| {
                    blocked(
                        RecoveryStatus::Malformed,
                        "gnome_default_collection_malformed",
                    )
                })?
                .trim_end_matches(['\r', '\n']);
            if name.is_empty()
                || name.len() > 255
                || name == "."
                || name == ".."
                || name.contains(['/', '\\', '\0'])
            {
                return Err(blocked(
                    RecoveryStatus::Malformed,
                    "gnome_default_collection_malformed",
                ));
            }
            let suffix = if name.ends_with(".keyring") {
                ""
            } else {
                ".keyring"
            };
            return Ok(format!("{directory}/{name}{suffix}"));
        }
        let path = format!("{directory}/login.keyring");
        if find(pool, job, &path, "gnome_keyring").await?.is_some() {
            return Ok(path);
        }
    }
    Ok(format!("{home}/.local/share/keyrings/login.keyring"))
}

/// Each selector requires all its exact text attributes. Alternative selectors
/// may overlap, but the union must identify exactly one decrypted item.
pub(crate) async fn recover_gnome<F: Filesystem>(
    context: PreparationContext<'_, F>,
    home: &str,
    selectors: &[&[(&str, &str)]],
) -> Result<ParserSecret>
where
    F::FileType: FileCommon,
{
    validate_gnome_selectors(selectors)?;
    let PreparationContext {
        pool,
        filesystem: fs,
        session,
        job,
        cancel,
    } = context;
    let path = gnome_path(pool, fs, job, home, cancel).await?;
    let bytes = read_dependency(
        pool,
        fs,
        job,
        &path,
        "gnome_keyring",
        MAX_STORE_BYTES,
        cancel,
    )
    .await?
    .ok_or_else(|| blocked(RecoveryStatus::MissingEvidence, "gnome_keyring_missing"))?;
    let store = GnomeKeyring::parse(&bytes).map_err(map_gnome_error)?;
    if store.indexed_items().is_empty() {
        return Err(blocked(
            RecoveryStatus::MissingEvidence,
            "credential_gnome_keyring_item_missing",
        ));
    }
    let (id, label) = credential(job, &path, "GNOME Keyring", home);
    let password = session.password(job, id, label)?;
    let unlocked =
        blocking(|| store.unlock_password(password.expose(), cancel)).map_err(map_gnome_error)?;
    job.method = Some("gnome_keyring_password".into());
    job.store_validation = Some("gnome_keyring_unkeyed_md5_checksum".into());
    let matching: Vec<_> = unlocked
        .items()
        .filter_map(|item| {
            selectors
                .iter()
                .copied()
                .find(|selector| matches_attributes(&item.attributes, selector))
        })
        .take(2)
        .collect();
    let selector = match matching.as_slice() {
        [selector] => *selector,
        [] => {
            return Err(blocked(
                RecoveryStatus::MissingEvidence,
                "credential_gnome_keyring_item_missing",
            ))
        }
        _ => {
            return Err(blocked(
                RecoveryStatus::MissingEvidence,
                "credential_gnome_keyring_item_ambiguous",
            ))
        }
    };
    let storage = unlocked
        .recover_secret(selector, cancel)
        .map_err(map_gnome_error)?;
    if let Some(source) = job.sources.iter_mut().find(|s| s.role == "gnome_keyring") {
        source.record_offsets = vec![u64::try_from(storage.index_offset())?];
    }
    Ok(ParserSecret::new(storage.expose().to_vec()))
}

fn validate_gnome_selectors(selectors: &[&[(&str, &str)]]) -> Result<()> {
    if selectors.is_empty()
        || selectors.iter().any(|selector| {
            let mut names = BTreeSet::new();
            selector.is_empty()
                || selector
                    .iter()
                    .any(|(name, _)| name.is_empty() || !names.insert(*name))
        })
    {
        return Err(blocked(
            RecoveryStatus::Malformed,
            "gnome_keyring_selector_invalid",
        ));
    }
    Ok(())
}

fn matches_attributes(attributes: &Attributes, selector: &[(&str, &str)]) -> bool {
    selector.iter().all(|(name, expected)| {
        matches!(attributes.get(*name), Some(AttributeValue::Text(Some(actual))) if actual == expected)
    })
}

fn credential(job: &RecoveryJob, path: &str, label: &str, home: &str) -> (String, String) {
    (
        scoped_id("recovery-store-", job.scope, job.inventory_run_id, path),
        format!("{label} password for {home:?}"),
    )
}

/// Only the Wallet/Default Wallet setting is interpreted. KConfig expansion or
/// localization requiring the live user's environment is explicitly unsupported.
fn configured_wallet(data: &[u8]) -> Result<Option<String>> {
    let text = std::str::from_utf8(data)
        .map_err(|_| blocked(RecoveryStatus::Malformed, "kwallet_settings_malformed"))?;
    let mut in_wallet = false;
    let mut name = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        if line.starts_with("[Wallet]") && line != "[Wallet]" {
            return Err(blocked(
                RecoveryStatus::Unsupported,
                "kwallet_settings_group_flags_unsupported",
            ));
        }
        if line.starts_with('[') {
            in_wallet = line == "[Wallet]";
            continue;
        }
        if !in_wallet {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim().starts_with("Default Wallet[") {
            return Err(blocked(
                RecoveryStatus::Unsupported,
                "kwallet_settings_expansion_unsupported",
            ));
        }
        if key.trim() != "Default Wallet" {
            continue;
        }
        if name.is_some() {
            return Err(blocked(
                RecoveryStatus::Malformed,
                "kwallet_settings_ambiguous",
            ));
        }
        let mut decoded = String::new();
        let mut chars = value.trim().chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                decoded.push(c);
                continue;
            }
            decoded.push(match chars.next() {
                Some('s') => ' ',
                Some('n') => '\n',
                Some('r') => '\r',
                Some('t') => '\t',
                Some('\\') => '\\',
                _ => {
                    return Err(blocked(
                        RecoveryStatus::Unsupported,
                        "kwallet_settings_escaping_unsupported",
                    ))
                }
            });
        }
        if decoded.len() > 255 {
            return Err(blocked(RecoveryStatus::LimitExceeded, "kwallet_name_limit"));
        }
        name = Some(if decoded.is_empty() {
            "kdewallet".into()
        } else {
            decoded
        });
    }
    Ok(name)
}

pub(crate) async fn wallet_path<F: Filesystem>(
    pool: &SqlitePool,
    fs: &mut F,
    job: &mut RecoveryJob,
    home: &str,
    cancel: Option<&AtomicBool>,
) -> Result<String>
where
    F::FileType: FileCommon,
{
    let root = home
        .strip_suffix("/root")
        .or_else(|| home.rsplit_once("/home/").map(|(root, _)| root))
        .ok_or_else(|| blocked(RecoveryStatus::Unsupported, "linux_user_scope_unknown"))?;
    let mut name = "kdewallet".to_string();
    for path in [
        format!("{root}/etc/xdg/kwalletrc"),
        format!("{home}/.config/kwalletrc"),
    ] {
        if let Some(data) = read_dependency(
            pool,
            fs,
            job,
            &path,
            "kwallet_settings",
            MAX_SETTINGS_BYTES,
            cancel,
        )
        .await?
        {
            if let Some(value) = configured_wallet(&data)? {
                name = value;
            }
        }
    }
    // KDE's filename encoding uses ';' instead of '%' and retains historical
    // allowed ASCII characters. Slash, backslash and UTF-8 bytes are encoded.
    let mut encoded = String::new();
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || b"^&'@{}[],$=!-#()%.+_\r\n\t\x0c\x0b ".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut encoded, ";{byte:02X}")?;
        }
    }
    Ok(format!("{home}/.local/share/kwalletd/{encoded}.kwl"))
}

pub(crate) async fn recover_wallet<F: Filesystem>(
    context: PreparationContext<'_, F>,
    home: &str,
    folder: &str,
    entry: &str,
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
    let path = wallet_path(pool, fs, job, home, cancel).await?;
    let bytes = read_dependency(pool, fs, job, &path, "kwallet", MAX_STORE_BYTES, cancel)
        .await?
        .ok_or_else(|| blocked(RecoveryStatus::MissingEvidence, "kwallet_missing"))?;
    let wallet = KWallet::parse(&bytes).map_err(map_wallet_error)?;
    let salt_path = format!(
        "{}.salt",
        path.strip_suffix(".kwl")
            .context("KWallet path has no extension")?
    );
    let salt = read_dependency(pool, fs, job, &salt_path, "kwallet_salt", 56, cancel)
        .await?
        .ok_or_else(|| blocked(RecoveryStatus::MissingEvidence, "kwallet_salt_missing"))?;
    if salt.len() != 56 {
        return Err(blocked(RecoveryStatus::Malformed, "kwallet_salt_invalid"));
    }
    if wallet
        .indexed_folders()
        .iter()
        .all(|folder| folder.entry_name_md5.is_empty())
    {
        return Err(blocked(
            RecoveryStatus::MissingEvidence,
            "credential_kwallet_entry_missing",
        ));
    }
    let (id, label) = credential(job, &path, "KWallet", home);
    let password = session.password(job, id, label)?;
    let unlocked = blocking(|| wallet.unlock_password(password.expose(), &salt, cancel))
        .map_err(map_wallet_error)?;
    job.method = Some("kwallet_password".into());
    job.store_validation = Some("kwallet_encrypted_unkeyed_checksum".into());
    let storage = unlocked
        .recover_password(folder, entry, cancel)
        .map_err(map_wallet_error)?;
    if let Some(source) = job.sources.iter_mut().find(|s| s.role == "kwallet") {
        source.record_offsets = vec![u64::try_from(storage.metadata().index_offset)?];
    }
    Ok(ParserSecret::new(storage.expose().to_vec()))
}

fn map_gnome_error(error: KeyringError) -> anyhow::Error {
    use KeyringError::*;
    match error {
        ChecksumFailed => blocked(
            RecoveryStatus::AuthenticationFailed,
            "gnome_keyring_checksum_failed",
        ),
        Cancelled => blocked(RecoveryStatus::Cancelled, "cancelled"),
        UnsupportedFormat | UnsupportedProtection => blocked(
            RecoveryStatus::Unsupported,
            "gnome_keyring_protection_unsupported",
        ),
        LimitExceeded { .. } => blocked(RecoveryStatus::LimitExceeded, "gnome_keyring_limit"),
        ItemNotFound => blocked(
            RecoveryStatus::MissingEvidence,
            "credential_gnome_keyring_item_missing",
        ),
        AmbiguousItem => blocked(
            RecoveryStatus::MissingEvidence,
            "credential_gnome_keyring_item_ambiguous",
        ),
        _ => blocked(RecoveryStatus::Malformed, "gnome_keyring_malformed"),
    }
}
fn map_wallet_error(error: WalletError) -> anyhow::Error {
    use WalletError::*;
    match error {
        ChecksumFailed => blocked(
            RecoveryStatus::AuthenticationFailed,
            "kwallet_checksum_failed",
        ),
        Cancelled => blocked(RecoveryStatus::Cancelled, "cancelled"),
        UnsupportedFormat | UnsupportedProtection => blocked(
            RecoveryStatus::Unsupported,
            "kwallet_protection_unsupported",
        ),
        LimitExceeded { .. } => blocked(RecoveryStatus::LimitExceeded, "kwallet_limit"),
        EntryNotFound => blocked(
            RecoveryStatus::MissingEvidence,
            "credential_kwallet_entry_missing",
        ),
        UnsupportedEntryType => blocked(
            RecoveryStatus::Unsupported,
            "kwallet_entry_type_unsupported",
        ),
        _ => blocked(RecoveryStatus::Malformed, "kwallet_malformed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_selectors_support_arbitrary_text_attributes() {
        let attributes = Attributes::from([
            ("account".into(), AttributeValue::Text(Some("alice".into()))),
            ("service".into(), AttributeValue::Text(Some("notes".into()))),
            ("counter".into(), AttributeValue::Integer(1)),
            ("absent".into(), AttributeValue::Text(None)),
        ]);
        assert!(matches_attributes(
            &attributes,
            &[("account", "alice"), ("service", "notes")]
        ));
        assert!(!matches_attributes(
            &attributes,
            &[("account", "alice"), ("service", "other")]
        ));
        assert!(!matches_attributes(&attributes, &[("counter", "1")]));
        assert!(!matches_attributes(&attributes, &[("absent", "")]));
        assert!(!matches_attributes(&attributes, &[("missing", "")]));
    }

    #[test]
    fn invalid_selector_sets_are_rejected_without_echoing_values() {
        for result in [
            validate_gnome_selectors(&[]),
            validate_gnome_selectors(&[&[]]),
            validate_gnome_selectors(&[&[("", "private-selector-value")]]),
            validate_gnome_selectors(&[&[("account", "alice"), ("account", "bob")]]),
        ] {
            let error = result.unwrap_err();
            let failure = error.downcast_ref::<PreparationFailure>().unwrap();
            assert_eq!(failure.status, RecoveryStatus::Malformed);
            assert_eq!(failure.reason, "gnome_keyring_selector_invalid");
            assert!(!error.to_string().contains("private-selector-value"));
        }
        assert!(
            validate_gnome_selectors(&[&[("account", "alice")], &[("service", "notes")]]).is_ok()
        );
    }
}
