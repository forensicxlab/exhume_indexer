//! Persistable recovery metadata. Credentials and recovered keys never belong here.
use exhume_artefacts::{ParserOptionSpec, ParserOptionType, ParserOptionValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryScope {
    pub evidence_id: i64,
    pub partition_id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPlatform {
    Windows,
    Macos,
    Linux,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Discovered,
    Complete,
    Partial,
    NeedsInput,
    MissingEvidence,
    Unsupported,
    AuthenticationFailed,
    ValidationFailed,
    Malformed,
    FileRead,
    LimitExceeded,
    BackendUnavailable,
    Cancelled,
    PersistenceFailed,
}
impl RecoveryStatus {
    pub fn is_published(self) -> bool {
        matches!(self, Self::Complete | Self::Partial)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySource {
    pub role: String,
    pub path: String,
    pub system_file_id: i64,
    pub fs_identifier: u64,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    /// Byte offsets in acquired bytes, never decrypted-buffer offsets.
    #[serde(default)]
    pub record_offsets: Vec<u64>,
}

/// Owned presentation of the existing parser declarations, safe for storage/IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryOptionSpec {
    pub name: String,
    pub label: String,
    pub description: String,
    pub value_type: ParserOptionType,
    pub required: bool,
    pub default: Option<ParserOptionValue>,
}
impl TryFrom<&ParserOptionSpec> for RecoveryOptionSpec {
    type Error = serde_json::Error;
    fn try_from(spec: &ParserOptionSpec) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::to_value(spec)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequirement {
    pub id: String,
    pub label: String,
    /// This dependency still requires input; satisfied dependencies stay auditable.
    pub needed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryJob {
    pub scope: RecoveryScope,
    pub target_id: String,
    pub artifact_id: i64,
    pub parser: String,
    pub application: String,
    pub primary_path: String,
    /// Application-defined evidence directory used to resolve its dependencies.
    pub root_path: String,
    pub platform: RecoveryPlatform,
    pub inventory_run_id: Option<i64>,
    pub status: RecoveryStatus,
    /// Static diagnostic code with no submitted values.
    pub reason: String,
    pub credentials: Vec<CredentialRequirement>,
    #[serde(default)]
    pub inputs: Vec<exhume_artefacts::ParserInputRequest>,
    pub method: Option<String>,
    pub option_specs: Vec<RecoveryOptionSpec>,
    /// Non-secret parser options only. Secret values are operation-local.
    pub parameters: BTreeMap<String, ParserOptionValue>,
    pub store_validation: Option<String>,
    pub output_validation: Option<String>,
    pub sources: Vec<RecoverySource>,
    pub object_count: u64,
    pub issue_count: u64,
    pub attempt_id: Option<i64>,
    /// A later failed attempt never replaces the last successful publication.
    pub published_attempt_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    pub id: String,
    pub label: String,
    pub targets: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub jobs: Vec<RecoveryJob>,
}
impl RecoveryReport {
    pub fn unresolved_count(&self) -> usize {
        self.jobs
            .iter()
            .filter(|job| !job.status.is_published())
            .count()
    }
    pub fn requests(&self) -> Vec<CredentialRequest> {
        let mut requests = BTreeMap::<String, CredentialRequest>::new();
        for job in &self.jobs {
            if !matches!(
                job.status,
                RecoveryStatus::NeedsInput | RecoveryStatus::AuthenticationFailed
            ) {
                continue;
            }
            for credential in job
                .credentials
                .iter()
                .filter(|credential| credential.needed)
            {
                let request =
                    requests
                        .entry(credential.id.clone())
                        .or_insert_with(|| CredentialRequest {
                            id: credential.id.clone(),
                            label: credential.label.clone(),
                            targets: Vec::new(),
                        });
                if !request.targets.contains(&job.target_id) {
                    request.targets.push(job.target_id.clone());
                }
            }
        }
        requests.into_values().collect()
    }
}

/// Byte and record limits apply per target; target discovery is bounded per scope.
#[derive(Debug, Clone)]
pub struct RecoveryLimits {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub records: u64,
    pub targets: usize,
}
impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            input_bytes: 8 * 1024 * 1024 * 1024,
            output_bytes: 512 * 1024 * 1024,
            records: 1_000_000,
            targets: 4096,
        }
    }
}
