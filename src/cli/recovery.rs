//! Terminal adaptation of the reusable recovery contracts.
use anyhow::{ensure, Context, Result};
use clap::{Arg, ArgAction, ArgMatches, Command};
use exhume_artefacts::{ParserOptionValue, ParserSecret};
use exhume_indexer::recovery::{RecoveryReport, RecoverySession};
use std::{
    collections::BTreeSet,
    io::{IsTerminal, Read},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub fn arguments(command: Command) -> Command {
    command
        .arg(Arg::new("retry_recovery").long("retry-recovery").action(ArgAction::SetTrue).requires("partition_id").conflicts_with_all(["extract_artefacts","identify_files"]).help("Retry recovery targets using the existing inventory."))
        .arg(Arg::new("recovery_target").long("recovery-target").action(ArgAction::Append).value_name("TARGET_ID").requires("retry_recovery").help("Retry only this target; repeat for more."))
        .arg(Arg::new("credential_file").long("credential-file").action(ArgAction::Append).value_name("STORE_ID=PATH").help("Read an exact acquired-store password, scoped to its reported ID; no newline trimming."))
        .arg(Arg::new("recovery_secret_file").long("recovery-secret-file").action(ArgAction::Append).value_name("TARGET_ID:OPTION=PATH").help("Read an exact secret for a declared parser option on one target."))
        .arg(Arg::new("recovery_option").long("recovery-option").action(ArgAction::Append).value_name("PARSER:OPTION=JSON").help("Set a declared non-secret parser option using a JSON string, integer or boolean."))
        .arg(Arg::new("no_recovery_input").long("no-recovery-input").action(ArgAction::SetTrue).help("Do not prompt; unresolved targets remain available for retry."))
}
pub struct RecoveryCli {
    pub retry: bool,
    pub selected: Vec<String>,
    passwords: Vec<(String, PathBuf)>,
    secrets: Vec<(String, String, PathBuf)>,
    parameters: Vec<(String, String, ParserOptionValue)>,
    no_input: bool,
}
fn entries(matches: &ArgMatches, name: &str) -> Result<Vec<(String, String)>> {
    let mut seen = BTreeSet::new();
    matches
        .get_many::<String>(name)
        .into_iter()
        .flatten()
        .map(|entry| {
            let (selector, value) = entry
                .split_once('=')
                .context("recovery input requires SELECTOR=VALUE")?;
            ensure!(
                !selector.is_empty() && !value.is_empty(),
                "recovery input requires SELECTOR=VALUE"
            );
            ensure!(seen.insert(selector), "duplicate recovery input selector");
            Ok((selector.into(), value.into()))
        })
        .collect()
}
fn pair(selector: &str) -> Result<(String, String)> {
    let (owner, option) = selector
        .split_once(':')
        .context("option selector requires OWNER:OPTION")?;
    ensure!(
        !owner.is_empty() && !option.is_empty(),
        "option selector requires OWNER:OPTION"
    );
    Ok((owner.into(), option.into()))
}
impl RecoveryCli {
    pub fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let passwords = entries(matches, "credential_file")?
            .into_iter()
            .map(|(id, path)| (id, path.into()))
            .collect();
        let secrets = entries(matches, "recovery_secret_file")?
            .into_iter()
            .map(|(selector, path)| {
                let (target, name) = pair(&selector)?;
                Ok((target, name, PathBuf::from(path)))
            })
            .collect::<Result<_>>()?;
        let parameters = entries(matches, "recovery_option")?
            .into_iter()
            .map(|(selector, value)| {
                let (parser, name) = pair(&selector)?;
                let value = serde_json::from_str(&value)
                    .context("recovery option must be a JSON string, boolean or integer")?;
                Ok((parser, name, value))
            })
            .collect::<Result<_>>()?;
        let options = Self {
            retry: matches.get_flag("retry_recovery"),
            selected: matches
                .get_many::<String>("recovery_target")
                .into_iter()
                .flatten()
                .cloned()
                .collect(),
            passwords,
            secrets,
            parameters,
            no_input: matches.get_flag("no_recovery_input"),
        };
        ensure!(
            options.retry
                || matches.get_flag("extract_artefacts")
                || (options.passwords.is_empty()
                    && options.secrets.is_empty()
                    && options.parameters.is_empty()),
            "recovery inputs require --extract-artefacts or --retry-recovery"
        );
        Ok(options)
    }
    pub fn load_secrets(&self, session: &mut RecoverySession) -> Result<()> {
        for (id, path) in &self.passwords {
            session.provide_password(id, read_secret(path)?)?;
        }
        for (target, name, path) in &self.secrets {
            session.provide_secret(target, name, read_secret(path)?)?;
        }
        for (parser, name, value) in &self.parameters {
            session.provide_parameter(parser, name, value.clone())?;
        }
        Ok(())
    }
    pub fn validate_scope(&self, report: &RecoveryReport) -> Result<()> {
        let selected: RecoveryReport = if self.selected.is_empty() {
            report.clone()
        } else {
            RecoveryReport {
                jobs: report
                    .jobs
                    .iter()
                    .filter(|job| self.selected.contains(&job.target_id))
                    .cloned()
                    .collect(),
            }
        };
        let mut session = RecoverySession::default();
        self.load_secrets(&mut session)?;
        session.validate_scope(&selected)
    }
    /// Prompt once per acquired store and once per requested parser secret.
    pub fn prompt(
        &self,
        report: &RecoveryReport,
        session: &mut RecoverySession,
    ) -> Result<Vec<String>> {
        if self.no_input || !std::io::stdin().is_terminal() {
            return Ok(Vec::new());
        }
        let mut retry = BTreeSet::new();
        for request in report.requests() {
            let label = format!(
                "{} ({} targets; Ctrl-D to defer): ",
                request.label,
                request.targets.len()
            );
            let Some(secret) = prompt(&label)? else {
                return Ok(retry.into_iter().collect());
            };
            session.provide_password(&request.id, secret)?;
            retry.extend(request.targets);
        }
        for job in &report.jobs {
            for request in &job.inputs {
                if request.value_type != exhume_artefacts::ParserOptionType::Secret {
                    continue;
                }
                let Some(secret) = prompt(&format!(
                    "{} — {} (Ctrl-D to defer): ",
                    job.application, request.label
                ))?
                else {
                    return Ok(retry.into_iter().collect());
                };
                session.provide_secret(&job.target_id, &request.name, secret)?;
                retry.insert(job.target_id.clone());
            }
        }
        Ok(retry.into_iter().collect())
    }
}
fn prompt(label: &str) -> Result<Option<ParserSecret>> {
    match rpassword::prompt_password(label) {
        Ok(value) => Ok(Some(ParserSecret::new(value.into_bytes()))),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(None)
        }
        Err(error) => {
            Err(anyhow::Error::new(error).context("could not read recovery secret from terminal"))
        }
    }
}
fn read_secret(path: &Path) -> Result<ParserSecret> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .context("could not open recovery secret file")?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "recovery secret file exceeds its byte limit"
    );
    Ok(ParserSecret::new(std::mem::take(&mut *bytes)))
}
