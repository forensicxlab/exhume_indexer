use anyhow::Result;
use exhume_artefacts::parsers::ParserRegistry;
use exhume_artefacts::{ObjectParsed, Parser as ArtefactParser, ParserInput};
use exhume_filesystem::filesystem::{FileCommon, FsFileReadSeek};
use exhume_filesystem::File;
use exhume_filesystem::Filesystem;
use regex::escape;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::fs;
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

        let objs =
            extract_artefact(&mut fs, &parser, 7, "/empty.exe").expect("empty file should skip");

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

        let objs = extract_artefact(&mut fs, &parser, 8, "/non-empty.exe")
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
    fs_identifier: u64,
    absolute_path: &str,
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

    // Adapter: Read+Seek backed by Filesystem::read_file_slice
    let rs = FsFileReadSeek::new(fs, record);

    // Collect parsed objects
    let mut out: Vec<ObjectParsed> = Vec::new();
    let mut sink = |obj: ObjectParsed| -> Result<()> {
        out.push(obj);
        Ok(())
    };

    parser.run_into(ParserInput::ReadSeek(Box::new(rs)), &mut sink)?;
    Ok(out)
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

        let objs = match extract_artefact(fs, &**parser, fs_identifier_i64 as u64, &abs_path) {
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

            if let Err(e) = sqlx::query(
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
            .bind(obj.parser)
            .bind(obj.kind)
            .bind(obj.text)
            .bind(obj.json.to_string())
            .execute(&mut *tx)
            .await
            {
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
