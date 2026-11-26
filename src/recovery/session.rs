use super::*;
use exhume_artefacts::{ParserOptionType, ParserOptionValue, ParserSecret};
use std::collections::BTreeMap;

/// Caller-owned secret lifetime. Store credentials can serve several apps in the
/// same evidence scope; parser secrets remain bound to one target and option.
#[derive(Debug, Default)]
pub struct RecoverySession {
    pub limits: RecoveryLimits,
    passwords: BTreeMap<String, ParserSecret>,
    secrets: BTreeMap<(String, String), ParserSecret>,
    parameters: BTreeMap<(String, String), ParserOptionValue>,
    target_parameters: BTreeMap<(String, String), ParserOptionValue>,
}
impl RecoverySession {
    pub fn provide_password(&mut self, id: &str, password: ParserSecret) -> Result<()> {
        ensure!(
            valid_id(id, "recovery-store-"),
            "invalid credential-store ID"
        );
        ensure!(
            password.expose().len() <= 1024 * 1024,
            "credential exceeds its byte limit"
        );
        self.passwords.insert(id.into(), password);
        Ok(())
    }
    pub fn provide_secret(
        &mut self,
        target: &str,
        option: &str,
        secret: ParserSecret,
    ) -> Result<()> {
        ensure!(
            valid_id(target, "recovery-target-"),
            "invalid recovery target ID"
        );
        ensure!(valid_option(option), "invalid secret option name");
        ensure!(
            secret.expose().len() <= 1024 * 1024,
            "secret exceeds its byte limit"
        );
        self.secrets.insert((target.into(), option.into()), secret);
        Ok(())
    }
    pub fn provide_parameter(
        &mut self,
        parser: &str,
        option: &str,
        value: ParserOptionValue,
    ) -> Result<()> {
        ensure!(
            valid_option(parser) && valid_option(option),
            "invalid parser option selector"
        );
        validate_value(&value)?;
        self.parameters
            .insert((parser.into(), option.into()), value);
        Ok(())
    }
    pub fn provide_target_parameter(
        &mut self,
        target: &str,
        option: &str,
        value: ParserOptionValue,
    ) -> Result<()> {
        ensure!(
            valid_id(target, "recovery-target-") && valid_option(option),
            "invalid target option selector"
        );
        validate_value(&value)?;
        self.target_parameters
            .insert((target.into(), option.into()), value);
        Ok(())
    }
    pub fn secret(&self, target: &str, option: &str) -> Option<&ParserSecret> {
        self.secrets.get(&(target.into(), option.into()))
    }
    /// Reject unknown or stale selectors before doing work. Passwords are scoped
    /// to acquired stores; secrets are validated against parser declarations.
    pub fn validate_scope(&self, report: &RecoveryReport) -> Result<()> {
        ensure!(
            self.passwords.len()
                + self.secrets.len()
                + self.parameters.len()
                + self.target_parameters.len()
                <= 4096,
            "too many recovery inputs"
        );
        ensure!(
            self.passwords
                .keys()
                .all(|id| report.jobs.iter().any(|job| job
                    .credentials
                    .iter()
                    .any(|credential| &credential.id == id))),
            "credential ID is outside the selected inventory scope"
        );
        for (target, name) in self.secrets.keys() {
            ensure!(
                report.jobs.iter().any(|job| &job.target_id == target
                    && job
                        .option_specs
                        .iter()
                        .any(|spec| &spec.name == name
                            && spec.value_type == ParserOptionType::Secret)),
                "secret target or option is outside the selected inventory scope"
            );
        }
        for (target, _) in self.target_parameters.keys() {
            ensure!(
                report.jobs.iter().any(|job| &job.target_id == target),
                "parameter target is outside the selected inventory scope"
            );
        }
        for (parser, _) in self.parameters.keys() {
            ensure!(
                report.jobs.iter().any(|job| &job.parser == parser),
                "parameter parser is outside the selected inventory scope"
            );
        }
        for job in &report.jobs {
            self.parameters_for(job)?;
        }
        Ok(())
    }
    /// Register the precise store dependency before requesting input. Neither an
    /// app ID nor a profile ID changes the identity of the same acquired store.
    pub fn password<'a>(
        &'a self,
        job: &mut RecoveryJob,
        id: String,
        label: String,
    ) -> Result<&'a ParserSecret> {
        let password = self.passwords.get(&id);
        job.credentials.retain(|credential| credential.id != id);
        job.credentials.push(CredentialRequirement {
            id,
            label,
            needed: password.is_none(),
        });
        password.ok_or_else(|| blocked(RecoveryStatus::NeedsInput, "credential_required"))
    }
    pub(super) fn parameters_for(
        &self,
        job: &RecoveryJob,
    ) -> Result<BTreeMap<String, ParserOptionValue>> {
        let mut values = job.parameters.clone();
        for ((parser, name), value) in &self.parameters {
            if parser == &job.parser {
                values.insert(name.clone(), value.clone());
            }
        }
        for ((target, name), value) in &self.target_parameters {
            if target == &job.target_id {
                values.insert(name.clone(), value.clone());
            }
        }
        for (name, value) in &values {
            let spec = job
                .option_specs
                .iter()
                .find(|spec| &spec.name == name)
                .context("undeclared recovery option")?;
            let kind = match value {
                ParserOptionValue::String(_) => ParserOptionType::String,
                ParserOptionValue::Boolean(_) => ParserOptionType::Boolean,
                ParserOptionValue::Integer(_) => ParserOptionType::Integer,
            };
            ensure!(
                spec.value_type == kind,
                "recovery option has the wrong type"
            );
        }
        Ok(values)
    }
    pub(super) fn apply_secrets(
        &self,
        job: &RecoveryJob,
        options: &mut ParserOptions,
    ) -> Result<()> {
        for ((target, name), secret) in &self.secrets {
            if target != &job.target_id {
                continue;
            }
            ensure!(
                job.option_specs
                    .iter()
                    .any(|spec| &spec.name == name && spec.value_type == ParserOptionType::Secret),
                "undeclared recovery secret"
            );
            options.insert_secret(name, ParserSecret::new(secret.expose().to_vec()))?;
        }
        Ok(())
    }
}
fn valid_option(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn validate_value(value: &ParserOptionValue) -> Result<()> {
    ensure!(
        !matches!(value,ParserOptionValue::String(text) if text.len()>65536),
        "parser option exceeds its byte limit"
    );
    Ok(())
}
