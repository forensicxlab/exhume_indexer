//! Offline, account-scoped DPAPI master-key discovery and authentication.
use super::*;
use exhume_artefacts::formats::dpapi::{DpapiError, MasterKey, MasterKeyFile};
pub(crate) struct Selection<'a> {
    pub home: &'a str,
    pub guid: &'a str,
}
pub(crate) async fn recover<F: Filesystem>(
    context: PreparationContext<'_, F>,
    selection: Selection<'_>,
) -> Result<MasterKey>
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
    let Selection { home, guid } = selection;
    let protect = format!("{home}/AppData/Roaming/Microsoft/Protect/");
    let rows = sqlx::query("SELECT id,identifier,absolute_path,size FROM system_files WHERE evidence_id=? AND partition_id=? AND is_dir=0 AND lower(name)=lower(?) AND instr(lower(replace(absolute_path,char(92),'/')),lower(?))=1 ORDER BY id LIMIT 33")
        .bind(job.scope.evidence_id).bind(job.scope.partition_id).bind(guid).bind(&protect).fetch_all(pool).await?;
    if rows.len() == 33 {
        return Err(blocked(
            RecoveryStatus::LimitExceeded,
            "dpapi_dependency_candidate_limit",
        ));
    }
    let mut matches = Vec::new();
    for row in rows {
        let source = source_row(&row, "dpapi_master_key")?;
        if let Some(rest) = source
            .path
            .replace('\\', "/")
            .to_ascii_lowercase()
            .strip_prefix(&protect.to_ascii_lowercase())
        {
            if rest.split('/').count() == 2 {
                matches.push(source);
            }
        }
    }
    if matches.len() != 1 {
        return Err(blocked(
            RecoveryStatus::MissingEvidence,
            if matches.is_empty() {
                "dpapi_master_key_missing"
            } else {
                "dpapi_master_key_ambiguous"
            },
        ));
    }
    let mut source = matches.remove(0);
    let sid = source
        .path
        .rsplit(['/', '\\'])
        .nth(1)
        .context("DPAPI master key has no SID directory")?
        .to_string();
    let id = scoped_id(
        "recovery-store-",
        job.scope,
        job.inventory_run_id,
        &format!("{}:{}", home.to_ascii_lowercase(), sid.to_ascii_uppercase()),
    );
    let bytes = read_source(fs, &mut source, 8 * 1024 * 1024, cancel);
    job.sources.push(source);
    let bytes = bytes?;
    let file = MasterKeyFile::parse(&bytes).map_err(map_error)?;
    file.check_local_password_protection(&sid)
        .map_err(map_error)?;
    if !file.metadata().guid.eq_ignore_ascii_case(guid) {
        return Err(blocked(
            RecoveryStatus::MissingEvidence,
            "dpapi_master_key_mismatch",
        ));
    }
    let password = session.password(
        job,
        id,
        format!("Windows local-account password for {home:?} ({sid})"),
    )?;
    let password = std::str::from_utf8(password.expose())
        .map_err(|_| blocked(RecoveryStatus::Malformed, "windows_password_requires_utf8"))?;
    let master =
        blocking(|| file.unlock_local_password(&sid, password, cancel)).map_err(map_error)?;
    job.store_validation = Some("dpapi_master_key".into());
    job.method = Some("windows_local_password_dpapi".into());
    Ok(master)
}
pub(crate) fn map_error(error: DpapiError) -> anyhow::Error {
    match error {
        DpapiError::AuthenticationFailed => blocked(
            RecoveryStatus::AuthenticationFailed,
            "dpapi_authentication_failed",
        ),
        DpapiError::Cancelled => blocked(RecoveryStatus::Cancelled, "cancelled"),
        DpapiError::UnsupportedAlgorithms { .. } | DpapiError::UnsupportedVersion { .. } => {
            blocked(RecoveryStatus::Unsupported, "dpapi_protection_unsupported")
        }
        DpapiError::LimitExceeded { .. } => blocked(RecoveryStatus::LimitExceeded, "dpapi_limit"),
        DpapiError::WrongMasterKey => {
            blocked(RecoveryStatus::MissingEvidence, "dpapi_master_key_mismatch")
        }
        _ => blocked(RecoveryStatus::Malformed, "dpapi_malformed"),
    }
}
