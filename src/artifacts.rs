use anyhow::{Context, Result};
use exhume_artefacts::parsers::ParserRegistry;
use exhume_artefacts::{
    CompanionPathRule, CompanionSpec, CompoundParserInput, ObjectParsed, Parser as ArtefactParser,
    ParserFileProvider, ParserInput, ParserSource,
};
use exhume_filesystem::filesystem::{FileCommon, FsFileReadSeek};
use exhume_filesystem::File;
use exhume_filesystem::Filesystem;
use regex::escape;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use sqlx::{Sqlite, Transaction};
use std::fs;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::{error, info};

use crate::{send_progress, IndexerEvent, IndexerEventType};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    System,
    Network,
    Users,
    Media,
    Application,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ArtifactPath {
    Literal(String),
    WithFlag {
        path: String,
        #[serde(default)]
        regexp: bool,
    },
}

impl ArtifactPath {
    pub fn to_regex(&self) -> String {
        match self {
            ArtifactPath::Literal(p) => {
                format!("^{}$", escape(p))
            }
            ArtifactPath::WithFlag { path, regexp } => {
                if *regexp {
                    path.clone()
                } else {
                    format!("^{}$", escape(path))
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    pub description: String,
    pub paths: Vec<ArtifactPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parser: Option<String>,
    pub tag: String,
    pub category: Category,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactSet {
    pub artifacts: Vec<Artifact>,
}

impl ArtifactSet {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }
}

/// Flat, serializable view of an artifact definition suitable for UI display.
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactCatalogEntry {
    pub name: String,
    pub description: String,
    pub paths: Vec<String>,
    pub parser: Option<String>,
    pub tag: String,
    pub category: Category,
    pub platform: String,
}

fn infer_platform(paths: &[ArtifactPath]) -> &'static str {
    for path_spec in paths {
        let p: &str = match path_spec {
            ArtifactPath::Literal(s) => s,
            ArtifactPath::WithFlag { path, .. } => path,
        };
        // iOS: always rooted under /private/var/mobile/
        if p.contains("/private/var/mobile") {
            return "iOS";
        }
        // Android: /data/data/, /data/system, /data/misc/, /storage/emulated/, etc.
        if p.contains("/data/data/")
            || p.contains("/data/system")
            || p.contains("/data/misc/")
            || p.contains("/storage/emulated/")
            || p.contains("/data/app/")
            || p.contains("/data/anr")
            || p.contains("/data/tombstones")
            || p.contains("/data/log")
        {
            return "Android";
        }
        // macOS: /private/ hierarchy or /Library/ or /Volumes/
        if p.contains("/private/")
            || (p.contains("Library/") && !p.contains('\\'))
            || p.contains("/Volumes/")
        {
            return "macOS";
        }
        // Windows: backslash separator, case-insensitive prefix, or drive-letter pattern
        if p.contains('\\') || p.contains("(?i)") || p.contains("[A-Z]:") {
            return "Windows";
        }
        // Linux: conventional unix paths
        if p.starts_with('/') || p.starts_with("^/") || p.starts_with("^(?:/") {
            return "Linux";
        }
    }
    "Unknown"
}

/// Return the embedded artifact catalog as a flat list ready for serialisation.
pub fn load_artifact_catalog() -> Vec<ArtifactCatalogEntry> {
    let yaml = include_str!("../artifacts.yaml");
    let set = match ArtifactSet::from_yaml_str(yaml) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    set.artifacts
        .into_iter()
        .map(|a| {
            let platform = infer_platform(&a.paths).to_string();
            let paths = a
                .paths
                .iter()
                .map(|p| match p {
                    ArtifactPath::Literal(s) => s.clone(),
                    ArtifactPath::WithFlag { path, .. } => path.clone(),
                })
                .collect();
            ArtifactCatalogEntry {
                name: a.name,
                description: a.description,
                paths,
                parser: a.parser,
                tag: a.tag,
                category: a.category,
                platform,
            }
        })
        .collect()
}

fn decode_system_file_row(row: &sqlx::sqlite::SqliteRow) -> Result<File, sqlx::Error> {
    Ok(File {
        id: row.try_get("id")?,
        // SQLite stores INTEGER as signed i64. Reinterpret wrapped values so
        // folder-backed identifiers above i64::MAX round-trip correctly.
        identifier: row.try_get::<i64, _>("identifier")? as u64,
        absolute_path: row.try_get("absolute_path")?,
        name: row.try_get("name")?,
        ftype: row.try_get("ftype")?,
        size: row.try_get::<i64, _>("size")? as u64,
        created: row
            .try_get::<Option<i64>, _>("created")?
            .map(|value| value as u64),
        modified: row
            .try_get::<Option<i64>, _>("modified")?
            .map(|value| value as u64),
        accessed: row
            .try_get::<Option<i64>, _>("accessed")?
            .map(|value| value as u64),
        permissions: row.try_get("permissions")?,
        owner: row.try_get("owner")?,
        group: row.try_get("group")?,
        display: row.try_get("display")?,
        sig_name: row.try_get("sig_name")?,
        sig_mime: row.try_get("sig_mime")?,
        sig_exts: row.try_get("sig_exts")?,
        metadata: row.try_get("metadata")?,
    })
}

#[cfg(test)]
mod tests {
    use super::{extract_artefact, ArtifactSet};
    use anyhow::Result;
    use exhume_artefacts::{ObjectParsed, Parser};
    use exhume_filesystem::filesystem::{DirectoryCommon, FileCommon, Filesystem};
    use exhume_filesystem::File as ExhumeFile;
    use serde_json::{json, Value};
    use std::error::Error;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct TestFile {
        id: u64,
        size: u64,
    }

    impl FileCommon for TestFile {
        fn id(&self) -> u64 {
            self.id
        }

        fn size(&self) -> u64 {
            self.size
        }

        fn is_dir(&self) -> bool {
            false
        }

        fn to_string(&self) -> String {
            format!("TestFile(id={}, size={})", self.id, self.size)
        }

        fn to_json(&self) -> Value {
            json!({
                "id": self.id,
                "size": self.size,
            })
        }
    }

    struct TestDirectory;

    impl DirectoryCommon for TestDirectory {
        fn file_id(&self) -> u64 {
            0
        }

        fn name(&self) -> &str {
            ""
        }

        fn to_string(&self) -> String {
            "TestDirectory".to_string()
        }

        fn to_json(&self) -> Value {
            json!({})
        }
    }

    struct TestFilesystem {
        file: TestFile,
        bytes: Vec<u8>,
    }

    impl Filesystem for TestFilesystem {
        type FileType = TestFile;
        type DirectoryType = TestDirectory;

        fn filesystem_type(&self) -> String {
            "test".to_string()
        }

        fn path_separator(&self) -> String {
            "/".to_string()
        }

        fn record_count(&mut self) -> u64 {
            1
        }

        fn block_size(&self) -> u64 {
            4096
        }

        fn get_metadata(&self) -> std::result::Result<Value, Box<dyn Error>> {
            Ok(json!({}))
        }

        fn get_metadata_pretty(&self) -> std::result::Result<String, Box<dyn Error>> {
            Ok("test".to_string())
        }

        fn get_file(
            &mut self,
            file_id: u64,
        ) -> std::result::Result<Self::FileType, Box<dyn Error>> {
            if file_id == self.file.id {
                Ok(self.file.clone())
            } else {
                Err("missing file".into())
            }
        }

        fn read_file_content(
            &mut self,
            _file: &Self::FileType,
        ) -> std::result::Result<Vec<u8>, Box<dyn Error>> {
            Ok(self.bytes.clone())
        }

        fn read_file_prefix(
            &mut self,
            _file: &Self::FileType,
            length: usize,
        ) -> std::result::Result<Vec<u8>, Box<dyn Error>> {
            Ok(self.bytes.iter().copied().take(length).collect())
        }

        fn read_file_slice(
            &mut self,
            _file: &Self::FileType,
            offset: u64,
            length: usize,
        ) -> std::result::Result<Vec<u8>, Box<dyn Error>> {
            let start = offset as usize;
            if start >= self.bytes.len() {
                return Ok(Vec::new());
            }

            let end = start.saturating_add(length).min(self.bytes.len());
            Ok(self.bytes[start..end].to_vec())
        }

        fn list_dir(
            &mut self,
            _file: &Self::FileType,
        ) -> std::result::Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
            Ok(Vec::new())
        }

        fn record_to_file(
            &self,
            file: &Self::FileType,
            file_id: u64,
            absolute_path: &str,
        ) -> ExhumeFile {
            ExhumeFile {
                id: None,
                identifier: file_id,
                absolute_path: absolute_path.to_string(),
                name: "test.bin".to_string(),
                ftype: "File".to_string(),
                size: file.size,
                created: None,
                modified: None,
                accessed: None,
                permissions: None,
                owner: None,
                group: None,
                display: None,
                sig_name: None,
                sig_mime: None,
                sig_exts: None,
                metadata: json!({}),
            }
        }

        fn get_root_file_id(&self) -> u64 {
            self.file.id
        }
    }

    #[derive(Default)]
    struct CountingParser {
        calls: AtomicUsize,
    }

    impl CountingParser {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl Parser for CountingParser {
        fn name(&self) -> &'static str {
            "test_parser"
        }

        fn run_into(
            &self,
            _input: exhume_artefacts::ParserInput,
            sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        ) -> Result<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            sink(ObjectParsed {
                parser: self.name(),
                kind: "test.object",
                text: "ok".to_string(),
                json: json!({ "ok": true }),
            })?;
            Ok(())
        }
    }

    #[test]
    fn embedded_artifacts_yaml_parses() {
        let yaml = include_str!("../artifacts.yaml");
        let artifact_set =
            ArtifactSet::from_yaml_str(yaml).expect("embedded artifacts.yaml should parse");
        assert!(
            !artifact_set.artifacts.is_empty(),
            "embedded artifacts.yaml should contain entries"
        );
    }

    #[test]
    fn extract_artefact_skips_empty_files() {
        let parser = CountingParser::default();
        let mut fs = TestFilesystem {
            file: TestFile { id: 7, size: 0 },
            bytes: Vec::new(),
        };

        let objs = extract_artefact(&mut fs, &parser, None, None, 7, "/empty.exe", Vec::new())
            .expect("empty file should skip");

        assert!(
            objs.is_empty(),
            "empty files should not emit parsed objects"
        );
        assert_eq!(parser.calls(), 0, "parser should not run for empty files");
    }

    #[test]
    fn extract_artefact_parses_non_empty_files() {
        let parser = CountingParser::default();
        let mut fs = TestFilesystem {
            file: TestFile { id: 8, size: 3 },
            bytes: vec![1, 2, 3],
        };

        let objs = extract_artefact(
            &mut fs,
            &parser,
            None,
            None,
            8,
            "/non-empty.exe",
            Vec::new(),
        )
        .expect("non-empty file should be parsed");

        assert_eq!(objs.len(), 1, "non-empty files should still be parsed");
        assert_eq!(parser.calls(), 1, "parser should run for non-empty files");
    }
}

pub async fn identify_artefacts(
    evidence_id: i64,
    partition_id: i64,
    pool: &SqlitePool,
    tx_progress: Option<Sender<IndexerEvent>>,
    artifacts_yaml_path: Option<&str>, // Allow injection or fallback to embedded
) {
    let default_yaml = include_str!("../artifacts.yaml");
    let stmt = r#"
        INSERT INTO artifacts (
            evidence_id,
            file_id,
            partition_id,
            name,
            description,
            parser,
            tag,
            category
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    "#;

    let yaml_text = match artifacts_yaml_path {
        Some(path) => match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                let msg = format!("Failed to read artifacts YAML file at {}: {}", path, e);
                send_progress(
                    &tx_progress,
                    IndexerEvent {
                        evidence_id,
                        event_type: IndexerEventType::Error,
                        message: msg.clone(),
                    },
                )
                .await;
                error!("{}", msg);
                return;
            }
        },
        None => default_yaml.to_string(),
    };

    let artifact_set: ArtifactSet = match ArtifactSet::from_yaml_str(&yaml_text) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("Failed to parse artifacts YAML: {}", e);
            send_progress(
                &tx_progress,
                IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Error,
                    message: msg.clone(),
                },
            )
            .await;
            error!("{}", msg);
            return;
        }
    };
    info!("Loaded {} artifact(s):", artifact_set.artifacts.len());

    // Make identify pass idempotent for this partition.
    if let Err(err) = sqlx::query(
        r#"
        DELETE FROM artifact_attachment_refs
        WHERE evidence_id = ?
          AND partition_id = ?;
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .execute(pool)
    .await
    {
        let msg = format!("Failed to clear existing attachment references: {err}");
        send_progress(
            &tx_progress,
            IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Error,
                message: msg.clone(),
            },
        )
        .await;
        error!("{}", msg);
        return;
    }

    if let Err(err) = sqlx::query(
        r#"
        DELETE FROM artifact_objects
        WHERE evidence_id = ?
          AND partition_id = ?;
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .execute(pool)
    .await
    {
        let msg = format!("Failed to clear existing parsed artefacts: {err}");
        send_progress(
            &tx_progress,
            IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Error,
                message: msg.clone(),
            },
        )
        .await;
        error!("{}", msg);
        return;
    }

    if let Err(err) = sqlx::query(
        r#"
        DELETE FROM artifacts
        WHERE evidence_id = ?
          AND partition_id = ?;
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .execute(pool)
    .await
    {
        let msg = format!("Failed to clear existing artefacts: {err}");
        send_progress(
            &tx_progress,
            IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Error,
                message: msg.clone(),
            },
        )
        .await;
        error!("{}", msg);
        return;
    }

    if let Err(err) = sqlx::query(
        r#"
        DELETE FROM timeline_events
        WHERE evidence_id = ?
          AND partition_id = ?
          AND artifact_object_id IS NOT NULL;
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .execute(pool)
    .await
    {
        let msg = format!("Failed to clear existing artifact timeline events: {err}");
        send_progress(
            &tx_progress,
            IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Error,
                message: msg.clone(),
            },
        )
        .await;
        error!("{}", msg);
        return;
    }

    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Info,
            message: "Identifying known artefacts…".to_string(),
        },
    )
    .await;

    // Fetch all files once to avoid redundant queries in the loop
    let all_files_res = sqlx::query(
        "SELECT * FROM system_files \
             WHERE evidence_id = ?1 \
             AND partition_id = ?2;",
    )
    .bind(evidence_id)
    .bind(partition_id)
    .fetch_all(pool)
    .await;

    let all_files = match all_files_res {
        Ok(rows) => {
            let mut files = Vec::with_capacity(rows.len());
            for row in rows {
                match decode_system_file_row(&row) {
                    Ok(file) => files.push(file),
                    Err(e) => {
                        let msg = format!(
                            "Failed to decode system_files row for partition {}: {}",
                            partition_id, e
                        );
                        send_progress(
                            &tx_progress,
                            IndexerEvent {
                                evidence_id,
                                event_type: IndexerEventType::Error,
                                message: msg.clone(),
                            },
                        )
                        .await;
                        error!("{}", msg);
                        return;
                    }
                }
            }
            files
        }
        Err(e) => {
            let msg = format!(
                "Failed to query DB for files in partition {}: {}",
                partition_id, e
            );
            send_progress(
                &tx_progress,
                IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Error,
                    message: msg.clone(),
                },
            )
            .await;
            error!("{}", msg);
            return;
        }
    };

    // Pre-compile all artifact regexes
    let mut compiled_artifacts = Vec::new();
    for artifact in &artifact_set.artifacts {
        let mut patterns = Vec::new();
        for path_spec in &artifact.paths {
            let pattern = path_spec.to_regex();
            match regex::Regex::new(&pattern) {
                Ok(rx) => patterns.push(rx),
                Err(e) => {
                    let msg = format!(
                        "Invalid regex pattern '{}' for artifact '{}': {e}",
                        pattern, artifact.name
                    );
                    send_progress(
                        &tx_progress,
                        IndexerEvent {
                            evidence_id,
                            event_type: IndexerEventType::Error,
                            message: msg.clone(),
                        },
                    )
                    .await;
                    error!("{}", msg);
                }
            }
        }
        if !patterns.is_empty() {
            compiled_artifacts.push((artifact, patterns));
        }
    }

    // Now iterate over all files once and check against all artifacts
    for file in &all_files {
        for (artifact, regexes) in &compiled_artifacts {
            let mut matched = false;
            for rx in regexes {
                if rx.is_match(&file.absolute_path) {
                    matched = true;
                    break;
                }
            }

            if matched {
                info!(
                    "Artifact matched ({}): {}",
                    artifact.name, file.absolute_path
                );
                if let Err(err) = sqlx::query(stmt)
                    .bind(evidence_id)
                    .bind(file.id.unwrap_or(0) as i64)
                    .bind(partition_id)
                    .bind(&artifact.name)
                    .bind(&artifact.description)
                    .bind(&artifact.parser)
                    .bind(&artifact.tag)
                    .bind(format!("{:?}", &artifact.category))
                    .execute(pool)
                    .await
                {
                    let msg = format!("Artifact insertion error: {err:?}");
                    send_progress(
                        &tx_progress,
                        IndexerEvent {
                            evidence_id,
                            event_type: IndexerEventType::Error,
                            message: msg.clone(),
                        },
                    )
                    .await;
                    error!("{}", msg);
                }
            }
        }
    }

    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Success,
            message: "Artefact identification complete.".to_string(),
        },
    )
    .await;
}

fn extract_artefact<F: Filesystem>(
    fs: &mut F,
    parser: &dyn ArtefactParser,
    artifact_id: Option<i64>,
    system_file_id: Option<i64>,
    fs_identifier: u64,
    absolute_path: &str,
    companions: Vec<ParserSource>,
) -> Result<Vec<ObjectParsed>>
where
    F::FileType: FileCommon,
{
    // Fetch FS record
    let record = match fs.get_file(fs_identifier) {
        Ok(r) => r,
        Err(_) => {
            // Fallback: try to get by path if ID lookup failed (e.g. empty FolderFS cache)
            fs.get_file_by_path(absolute_path, fs_identifier)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
        }
    };

    if record.size() == 0 {
        info!(
            "Skipping artefact extraction for empty file: {} (fs_identifier={})",
            absolute_path, fs_identifier
        );
        return Ok(Vec::new());
    }

    // Collect parsed objects
    let mut out: Vec<ObjectParsed> = Vec::new();
    let mut sink = |obj: ObjectParsed| -> Result<()> {
        out.push(obj);
        Ok(())
    };

    if parser.companion_specs().is_empty() {
        // Adapter: Read+Seek backed by Filesystem::read_file_slice
        let rs = FsFileReadSeek::new(fs, record);
        parser.run_into(ParserInput::ReadSeek(Box::new(rs)), &mut sink)?;
    } else {
        let primary = ParserSource::new(
            "primary",
            absolute_path,
            artifact_id,
            system_file_id,
            Some(fs_identifier),
        );
        let input = ParserInput::Compound(CompoundParserInput {
            primary,
            companions,
            provider: Box::new(FilesystemParserFileProvider { fs }),
        });
        parser.run_into(input, &mut sink)?;
    }

    Ok(out)
}

struct FilesystemParserFileProvider<'a, F>
where
    F: Filesystem,
    F::FileType: FileCommon,
{
    fs: &'a mut F,
}

impl<F> ParserFileProvider for FilesystemParserFileProvider<'_, F>
where
    F: Filesystem,
    F::FileType: FileCommon,
{
    fn copy_to(&mut self, source: &ParserSource, writer: &mut dyn Write) -> Result<()> {
        let record = match source.fs_identifier {
            Some(identifier) => match self.fs.get_file(identifier) {
                Ok(record) => record,
                Err(_) => self
                    .fs
                    .get_file_by_path(&source.original_path, identifier)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?,
            },
            None => self
                .fs
                .get_file_by_path(&source.original_path, 0)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
        };

        let mut reader = FsFileReadSeek::new(self.fs, record);
        std::io::copy(&mut reader, writer).with_context(|| {
            format!(
                "failed to copy parser source '{}' ({})",
                source.role, source.original_path
            )
        })?;
        Ok(())
    }
}

async fn resolve_companion_sources(
    tx: &mut Transaction<'_, Sqlite>,
    evidence_id: i64,
    partition_id: i64,
    primary_path: &str,
    specs: &[CompanionSpec],
) -> Result<Vec<ParserSource>> {
    let mut companions = Vec::new();

    for spec in specs {
        let candidate_path = match spec.path_rule {
            CompanionPathRule::Suffix(suffix) => format!("{primary_path}{suffix}"),
            CompanionPathRule::Sibling(filename) => match primary_path.rfind('/') {
                Some(idx) => format!("{}{}", &primary_path[..=idx], filename),
                None => filename.to_string(),
            },
        };

        let row = sqlx::query(
            r#"
            SELECT
                sf.id AS system_file_id,
                sf.identifier AS fs_identifier,
                sf.absolute_path AS absolute_path,
                a.id AS artifact_id
            FROM system_files sf
            LEFT JOIN artifacts a
              ON a.evidence_id = sf.evidence_id
             AND a.partition_id = sf.partition_id
             AND a.file_id = sf.id
            WHERE sf.evidence_id = ?
              AND sf.partition_id = ?
              AND sf.absolute_path = ?
            ORDER BY a.id
            LIMIT 1;
            "#,
        )
        .bind(evidence_id)
        .bind(partition_id)
        .bind(&candidate_path)
        .fetch_optional(&mut **tx)
        .await?;

        match row {
            Some(row) => {
                let artifact_id: Option<i64> = row.try_get("artifact_id")?;
                let system_file_id: i64 = row.try_get("system_file_id")?;
                let fs_identifier: i64 = row.try_get("fs_identifier")?;
                let absolute_path: String = row.try_get("absolute_path")?;
                companions.push(ParserSource::new(
                    spec.role,
                    absolute_path,
                    artifact_id,
                    Some(system_file_id),
                    Some(fs_identifier as u64),
                ));
            }
            None if spec.required => {
                anyhow::bail!(
                    "required companion '{}' not found for {} at {}",
                    spec.role,
                    primary_path,
                    candidate_path
                );
            }
            None => {}
        }
    }

    Ok(companions)
}

#[derive(Debug)]
struct ResolvedAttachmentFile {
    id: i64,
    identifier: i64,
    absolute_path: String,
    host_path: Option<String>,
    sig_mime: Option<String>,
    name: Option<String>,
    size: Option<i64>,
}

async fn insert_attachment_ref(
    tx: &mut Transaction<'_, Sqlite>,
    evidence_id: i64,
    partition_id: i64,
    artifact_object_id: i64,
    parser: &str,
    object_json: &Value,
) -> Result<()> {
    let local_path = json_string(object_json, &["media", "local_path"])
        .or_else(|| json_string(object_json, &["attachment", "local_path"]));
    let source_path = json_string(object_json, &["source", "path"]);
    let kind = json_string(object_json, &["attachment", "kind"]);
    let is_location = kind.as_deref() == Some("location");
    let resolved = match local_path.as_deref() {
        Some(path) => {
            resolve_attachment_file(tx, evidence_id, partition_id, source_path.as_deref(), path)
                .await?
        }
        None => None,
    };

    sqlx::query(
        r#"
        INSERT INTO artifact_attachment_refs (
            evidence_id,
            partition_id,
            artifact_object_id,
            parser,
            app,
            platform,
            media_rowid,
            message_rowid,
            chat_rowid,
            local_path,
            thumbnail_local_path,
            remote_url,
            title,
            kind,
            mime,
            file_name,
            file_size,
            duration_seconds,
            width,
            height,
            latitude,
            longitude,
            resolved_file_id,
            resolved_fs_identifier,
            resolved_absolute_path,
            resolved_host_path,
            resolved_sig_mime,
            resolved_name,
            resolved_size,
            preview_mime,
            preview_base64,
            json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .bind(artifact_object_id)
    .bind(parser)
    .bind(json_string(object_json, &["app"]))
    .bind(json_string(object_json, &["platform"]))
    .bind(json_i64(object_json, &["media", "rowid"]))
    .bind(json_i64(object_json, &["message", "rowid"]))
    .bind(json_i64(object_json, &["chat", "rowid"]))
    .bind(local_path)
    .bind(json_string(object_json, &["media", "thumbnail_local_path"]))
    .bind(json_string(object_json, &["media", "url"]))
    .bind(json_string(object_json, &["media", "title"]))
    .bind(kind)
    .bind(json_string(object_json, &["attachment", "mime"]))
    .bind(json_string(object_json, &["attachment", "file_name"]))
    .bind(json_i64(object_json, &["media", "file_size"]))
    .bind(json_f64(object_json, &["media", "movie_duration"]))
    .bind(json_i64(object_json, &["media", "width"]))
    .bind(json_i64(object_json, &["media", "height"]))
    .bind(if is_location {
        json_f64(object_json, &["media", "location", "latitude"])
    } else {
        None
    })
    .bind(if is_location {
        json_f64(object_json, &["media", "location", "longitude"])
    } else {
        None
    })
    .bind(resolved.as_ref().map(|file| file.id))
    .bind(resolved.as_ref().map(|file| file.identifier))
    .bind(resolved.as_ref().map(|file| file.absolute_path.clone()))
    .bind(resolved.as_ref().and_then(|file| file.host_path.clone()))
    .bind(resolved.as_ref().and_then(|file| file.sig_mime.clone()))
    .bind(resolved.as_ref().and_then(|file| file.name.clone()))
    .bind(resolved.as_ref().and_then(|file| file.size))
    .bind(json_string(object_json, &["preview", "mime"]))
    .bind(json_string(object_json, &["preview", "data"]))
    .bind(object_json.to_string())
    .execute(&mut **tx)
    .await?;

    Ok(())
}

async fn resolve_attachment_file(
    tx: &mut Transaction<'_, Sqlite>,
    evidence_id: i64,
    partition_id: i64,
    source_path: Option<&str>,
    local_path: &str,
) -> Result<Option<ResolvedAttachmentFile>> {
    let root = source_root(source_path).unwrap_or_default();
    let candidate_message = format!("{root}/Message/{local_path}");
    let candidate_root = format!("{root}/{local_path}");
    let candidate_shared_message =
        format!("{root}/net.whatsapp.WhatsApp.shared/Message/{local_path}");
    let candidate_shared = format!("{root}/net.whatsapp.WhatsApp.shared/{local_path}");
    let suffix_pattern = format!("%/{}", escape_sql_like(local_path));

    let row = sqlx::query(
        r#"
        SELECT
            id,
            identifier,
            absolute_path,
            host_path,
            sig_mime,
            name,
            size
        FROM system_files
        WHERE evidence_id = ?
          AND partition_id = ?
          AND is_dir = 0
          AND (
            absolute_path = ?
            OR absolute_path = ?
            OR absolute_path = ?
            OR absolute_path = ?
            OR absolute_path LIKE ? ESCAPE '\'
          )
        ORDER BY
          CASE
            WHEN absolute_path = ? THEN 0
            WHEN absolute_path = ? THEN 1
            WHEN absolute_path = ? THEN 2
            WHEN absolute_path = ? THEN 3
            ELSE 4
          END,
          LENGTH(absolute_path) ASC
        LIMIT 1;
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .bind(&candidate_message)
    .bind(&candidate_root)
    .bind(&candidate_shared_message)
    .bind(&candidate_shared)
    .bind(&suffix_pattern)
    .bind(&candidate_message)
    .bind(&candidate_root)
    .bind(&candidate_shared_message)
    .bind(&candidate_shared)
    .fetch_optional(&mut **tx)
    .await?;

    row.map(|row| {
        Ok(ResolvedAttachmentFile {
            id: row.try_get("id")?,
            identifier: row.try_get("identifier")?,
            absolute_path: row.try_get("absolute_path")?,
            host_path: row.try_get("host_path")?,
            sig_mime: row.try_get("sig_mime")?,
            name: row.try_get("name")?,
            size: row.try_get("size")?,
        })
    })
    .transpose()
}

fn source_root(path: Option<&str>) -> Option<String> {
    let path = path?;
    for suffix in [
        "/net.whatsapp.WhatsApp.shared/ChatStorage.sqlite",
        "/ChatStorage.sqlite",
    ] {
        if let Some(root) = path.strip_suffix(suffix) {
            return Some(root.to_string());
        }
    }

    None
}

fn escape_sql_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn json_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }

    match current {
        Value::String(value) if !value.trim().is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn json_i64(value: &Value, path: &[&str]) -> Option<i64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }

    current
        .as_i64()
        .or_else(|| current.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| {
            current
                .as_str()
                .and_then(|value| value.trim().parse::<i64>().ok())
        })
}

fn json_f64(value: &Value, path: &[&str]) -> Option<f64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }

    current.as_f64().or_else(|| {
        current
            .as_str()
            .and_then(|value| value.trim().parse::<f64>().ok())
    })
}

pub async fn extract_artefacts<F: Filesystem>(
    evidence_id: i64,
    partition_id: i64,
    pool: &SqlitePool,
    fs: &mut F,
    registry: &ParserRegistry,
    tx_progress: Option<Sender<IndexerEvent>>,
    cancel_token: Option<Arc<AtomicBool>>,
) where
    F::FileType: FileCommon,
{
    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Info,
            message: "Starting artefact extraction…".to_string(),
        },
    )
    .await;

    // Pull artefacts that specify a parser, joined to system_files to recover the FS identifier.
    let rows_res = sqlx::query(
        r#"
        SELECT
            a.id            AS artifact_id,
            a.file_id       AS file_id,
            a.parser        AS parser_name,
            sf.identifier   AS fs_identifier,
            sf.absolute_path AS absolute_path
        FROM artifacts a
        JOIN system_files sf
          ON sf.id = a.file_id
        WHERE a.evidence_id  = ?
          AND a.partition_id = ?
          AND a.parser IS NOT NULL
          AND TRIM(a.parser) <> ''
        ORDER BY a.id;
        "#,
    )
    .bind(evidence_id)
    .bind(partition_id)
    .fetch_all(pool)
    .await;

    let rows = match rows_res {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("Failed to list artefacts to extract: {e:?}");
            send_progress(
                &tx_progress,
                IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Error,
                    message: msg.clone(),
                },
            )
            .await;
            error!("{}", msg);
            return;
        }
    };

    if rows.is_empty() {
        send_progress(
            &tx_progress,
            IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Success,
                message: "No artefacts with a parser to extract.".to_string(),
            },
        )
        .await;
        return;
    }

    let total = rows.len() as u64;

    // Write parsed objects in one transaction for this partition.
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            let msg = format!("Could not open DB transaction for extraction: {e:?}");
            send_progress(
                &tx_progress,
                IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Error,
                    message: msg.clone(),
                },
            )
            .await;
            error!("{}", msg);
            return;
        }
    };

    let mut processed_files = 0u64;
    let mut emitted_objects = 0u64;

    for row in rows {
        if let Some(token) = &cancel_token {
            if token.load(Ordering::Relaxed) {
                // Abort processing but keep what hasn't been reverted
                break;
            }
        }

        processed_files += 1;

        let artifact_id: i64 = row.get("artifact_id");
        let file_id: Option<i64> = row.get("file_id");
        let parser_name: String = row.get("parser_name");
        let parser_name = parser_name.trim();
        let fs_identifier_i64: i64 = row.get("fs_identifier");
        let abs_path: String = row.get("absolute_path");

        let parser_opt = registry.get(parser_name);

        let parser = match parser_opt {
            Some(p) => p,
            None => {
                let available_parsers: Vec<&str> = registry.keys().cloned().collect();
                let msg = format!(
                    "Artefact '{}' references unknown parser '{}' (file: {}). Available parsers: {:?}",
                    artifact_id, parser_name, abs_path, available_parsers
                );
                send_progress(
                    &tx_progress,
                    IndexerEvent {
                        evidence_id,
                        event_type: IndexerEventType::Error,
                        message: msg.clone(),
                    },
                )
                .await;
                error!("{}", msg);
                continue;
            }
        };

        let companions = match resolve_companion_sources(
            &mut tx,
            evidence_id,
            partition_id,
            &abs_path,
            parser.companion_specs(),
        )
        .await
        {
            Ok(companions) => companions,
            Err(e) => {
                let msg = format!(
                    "Failed to resolve parser companions (parser={}, file={}): {e:?}",
                    parser_name, abs_path
                );
                send_progress(
                    &tx_progress,
                    IndexerEvent {
                        evidence_id,
                        event_type: IndexerEventType::Error,
                        message: msg.clone(),
                    },
                )
                .await;
                error!("{}", msg);
                continue;
            }
        };

        let objs = match extract_artefact(
            fs,
            &**parser,
            Some(artifact_id),
            file_id,
            fs_identifier_i64 as u64,
            &abs_path,
            companions,
        ) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!(
                    "Extraction failed (parser={}, file={}): {e:?}",
                    parser_name, abs_path
                );
                send_progress(
                    &tx_progress,
                    IndexerEvent {
                        evidence_id,
                        event_type: IndexerEventType::Error,
                        message: msg.clone(),
                    },
                )
                .await;
                error!("{}", msg);
                continue;
            }
        };

        for obj in objs {
            emitted_objects += 1;

            // Must be called before obj fields are moved out below.
            let tl_events = parser.extract_timeline_events(&obj);

            let object_parser = obj.parser;
            let object_kind = obj.kind;
            let object_text = obj.text;
            let object_json = obj.json;
            let object_json_text = object_json.to_string();

            let insert_result = sqlx::query(
                r#"
                INSERT INTO artifact_objects (
                    evidence_id,
                    partition_id,
                    artifact_id,
                    file_id,
                    parser,
                    kind,
                    text,
                    json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                "#,
            )
            .bind(evidence_id)
            .bind(partition_id)
            .bind(artifact_id)
            .bind(file_id)
            .bind(object_parser)
            .bind(object_kind)
            .bind(object_text)
            .bind(&object_json_text)
            .execute(&mut *tx)
            .await;

            let insert_result = match insert_result {
                Ok(result) => result,
                Err(e) => {
                    let msg = format!("DB insert error for parsed object: {e:?}");
                    send_progress(
                        &tx_progress,
                        IndexerEvent {
                            evidence_id,
                            event_type: IndexerEventType::Error,
                            message: msg.clone(),
                        },
                    )
                    .await;
                    error!("{}", msg);
                    continue;
                }
            };

            let artifact_object_id = insert_result.last_insert_rowid();

            for tl_event in tl_events {
                if let Err(e) = sqlx::query(
                    r#"
                    INSERT INTO timeline_events (
                        evidence_id, partition_id, ts, source, event_type,
                        description, file_id, artifact_object_id, actor
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(evidence_id)
                .bind(partition_id)
                .bind(tl_event.ts_unix_ms)
                .bind(object_parser)
                .bind(tl_event.event_type)
                .bind(tl_event.description)
                .bind(file_id)
                .bind(artifact_object_id)
                .bind(tl_event.actor)
                .execute(&mut *tx)
                .await
                {
                    error!("Timeline event insert error (parser={object_parser}): {e:?}");
                }
            }

            if object_kind == "mobile.communication.attachment" {
                if let Err(e) = insert_attachment_ref(
                    &mut tx,
                    evidence_id,
                    partition_id,
                    artifact_object_id,
                    object_parser,
                    &object_json,
                )
                .await
                {
                    let msg = format!("DB insert error for attachment reference: {e:?}");
                    send_progress(
                        &tx_progress,
                        IndexerEvent {
                            evidence_id,
                            event_type: IndexerEventType::Error,
                            message: msg.clone(),
                        },
                    )
                    .await;
                    error!("{}", msg);
                }
            }
        }

        if processed_files % 50 == 0 || processed_files == total {
            send_progress(&tx_progress, IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Progress { current: processed_files, total },
                message: format!(
                    "Artefact extraction: {processed_files}/{total} files, {emitted_objects} objects emitted…"
                ),
            }).await;
        }
    }

    if let Err(e) = tx.commit().await {
        let msg = format!("Extraction commit error: {e:?}");
        send_progress(
            &tx_progress,
            IndexerEvent {
                evidence_id,
                event_type: IndexerEventType::Error,
                message: msg.clone(),
            },
        )
        .await;
        error!("{}", msg);
        return;
    }

    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Success,
            message: format!(
            "Artefact extraction done: processed {total} files, emitted {emitted_objects} objects."
        ),
        },
    )
    .await;

    info!(
        "Artefact extraction done evidence_id={evidence_id} partition_id={partition_id}: \
         processed={total} emitted={emitted_objects}"
    );
}
