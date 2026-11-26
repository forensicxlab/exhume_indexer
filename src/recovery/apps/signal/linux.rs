use super::*;
use serde::Deserialize;

/// Recognize supported package directories and a standard owning account. A
/// mounted/extracted volume prefix is retained; another user's store is never
/// searched. XDG data/config directory overrides require explicit key recovery.
pub(super) fn owner(profile: &str) -> Option<(&str, bool)> {
    let (home, name) = profile
        .rsplit_once("/.config/")
        .or_else(|| profile.rsplit_once("/.var/app/org.signal.Signal/config/"))?;
    let beta = match name {
        "Signal" | "Signal AppImage" => false,
        "Signal Beta" | "Signal Beta AppImage" => true,
        _ => return None,
    };
    if !home.ends_with("/root")
        && !home
            .rsplit_once("/home/")
            .is_some_and(|(_, user)| !user.is_empty() && !user.contains('/'))
    {
        return None;
    }
    Some((home, beta))
}

#[derive(Clone, Copy)]
enum Store {
    Gnome,
    KWallet,
}

pub(super) async fn recover_key<F: Filesystem>(
    pool: &SqlitePool,
    fs: &mut F,
    session: &RecoverySession,
    job: &mut RecoveryJob,
    config: &SignalKeyEnvelope,
    configuration: &[u8],
    cancel: Option<&AtomicBool>,
) -> Result<ParserSecret>
where
    F::FileType: FileCommon,
{
    if config.kind() == EnvelopeKind::V10 {
        job.method = Some("linux_v10_legacy_obfuscation".into());
        return config.recover_linux(None, cancel).map_err(map_signal_error);
    }
    if config.kind() != EnvelopeKind::V11 {
        return Err(blocked(
            RecoveryStatus::Unsupported,
            "linux_key_envelope_unsupported",
        ));
    }
    let (home, beta) = owner(&job.root_path)
        .ok_or_else(|| blocked(RecoveryStatus::Unsupported, "linux_user_scope_unknown"))?;
    let home = home.to_string();
    // Deserialize only routing metadata: do not copy keys into a generic JSON
    // value or use a backend label as authority for the recovered plaintext.
    #[derive(Deserialize)]
    struct Routing {
        #[serde(rename = "safeStorageBackend")]
        backend: Option<String>,
    }
    let route: Routing = serde_json::from_slice(configuration).map_err(|_| {
        blocked(
            RecoveryStatus::Malformed,
            "linux_backend_metadata_malformed",
        )
    })?;
    let store = match route.backend.as_deref() {
        Some("gnome_libsecret") => Store::Gnome,
        Some("kwallet" | "kwallet5" | "kwallet6") => Store::KWallet,
        Some(_) => {
            return Err(blocked(
                RecoveryStatus::Unsupported,
                "linux_backend_unsupported",
            ))
        }
        None => {
            // Legacy configurations can omit the backend. A unique acquired
            // store is usable; two providers are not an invitation to try both.
            let gnome = providers::linux::gnome_path(pool, fs, job, &home, cancel).await?;
            let wallet = providers::linux::wallet_path(pool, fs, job, &home, cancel).await?;
            let mut candidates = Vec::new();
            for (path, role) in [(&gnome, "gnome_keyring"), (&wallet, "kwallet")] {
                if let Some(source) = find(pool, job, path, role).await? {
                    candidates.push(source);
                }
            }
            match candidates.as_slice() {
                [source] => {
                    if source.role == "gnome_keyring" {
                        Store::Gnome
                    } else {
                        Store::KWallet
                    }
                }
                [] => {
                    return Err(blocked(
                        RecoveryStatus::MissingEvidence,
                        "linux_key_store_missing",
                    ))
                }
                _ => {
                    job.sources.extend(candidates);
                    return Err(blocked(
                        RecoveryStatus::MissingEvidence,
                        "linux_key_store_ambiguous",
                    ));
                }
            }
        }
    };
    let storage = match store {
        Store::Gnome => {
            let applications = if beta {
                ["Signal Beta", "signal-beta"]
            } else {
                ["Signal", "signal"]
            };
            let attributes = applications.map(|application| {
                [
                    ("application", application),
                    ("xdg:schema", "chrome_libsecret_os_crypt_password_v2"),
                ]
            });
            let selectors = attributes
                .each_ref()
                .map(|attributes| attributes.as_slice());
            providers::linux::recover_gnome(
                PreparationContext {
                    pool,
                    filesystem: fs,
                    session,
                    job,
                    cancel,
                },
                &home,
                &selectors,
            )
            .await?
        }
        Store::KWallet => {
            providers::linux::recover_wallet(
                PreparationContext {
                    pool,
                    filesystem: fs,
                    session,
                    job,
                    cancel,
                },
                &home,
                "Chromium Keys",
                "Chromium Safe Storage",
            )
            .await?
        }
    };
    config
        .recover_linux(Some(storage.expose()), cancel)
        .map_err(map_signal_error)
}
