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
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc::Sender;
use tracing::{error, info};

use crate::{send_progress, IndexerEvent, IndexerEventType, ParserProgressPhase};

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
        // macOS: /private/ hierarchy, Apple library/volume paths, and
        // filesystem-root stores whose names are unique to macOS.
        if p.contains("/private/")
            || (p.contains("Library/") && !p.contains('\\'))
            || p.contains("/Volumes/")
            || p.contains("/.Spotlight-V100/")
            || p.contains("/\\.Spotlight-V100/")
            || p.contains("/.fseventsd/")
            || p.contains("/\\.fseventsd/")
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
    use super::{
        attachment_local_path, attachment_path_candidates, extract_artefact, infer_platform,
        resolve_attachment_file, resolve_attachment_files_batch, strip_apfs_volume_namespace,
        ArtifactPath, ArtifactSet,
    };
    use anyhow::Result;
    use exhume_artefacts::{ObjectParsed, Parser};
    use exhume_filesystem::filesystem::{DirectoryCommon, FileCommon, Filesystem};
    use exhume_filesystem::File as ExhumeFile;
    use serde_json::{json, Value};
    use sqlx::sqlite::SqlitePoolOptions;
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

    struct SourceAwareParser;

    impl Parser for SourceAwareParser {
        fn name(&self) -> &'static str {
            "source_aware_test_parser"
        }

        fn requires_source_metadata(&self) -> bool {
            true
        }

        fn run_into(
            &self,
            input: exhume_artefacts::ParserInput,
            sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        ) -> Result<()> {
            let exhume_artefacts::ParserInput::Compound(mut input) = input else {
                anyhow::bail!("source-aware parser did not receive compound input");
            };
            let mut bytes = Vec::new();
            input.provider.copy_to(&input.primary, &mut bytes)?;
            sink(ObjectParsed {
                parser: self.name(),
                kind: "test.source_aware",
                text: input.primary.original_path.clone(),
                json: json!({
                    "path": input.primary.original_path,
                    "artifact_id": input.primary.artifact_id,
                    "system_file_id": input.primary.system_file_id,
                    "fs_identifier": input.primary.fs_identifier,
                    "bytes": bytes,
                }),
            })
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
    fn embedded_parser_bindings_exist_in_registry() {
        let artifact_set = ArtifactSet::from_yaml_str(include_str!("../artifacts.yaml"))
            .expect("embedded artifacts.yaml should parse");
        let registry = exhume_artefacts::parsers::build_registry();
        let mut missing = artifact_set
            .artifacts
            .iter()
            .filter_map(|artifact| artifact.parser.as_deref())
            .filter(|parser| !registry.contains_key(parser))
            .collect::<Vec<_>>();
        missing.sort_unstable();
        missing.dedup();
        assert!(
            missing.is_empty(),
            "catalog references unregistered parsers: {missing:?}"
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

    #[test]
    fn source_aware_parser_receives_primary_provenance_without_companions() {
        let mut fs = TestFilesystem {
            file: TestFile { id: 9, size: 3 },
            bytes: vec![4, 5, 6],
        };

        let objects = extract_artefact(
            &mut fs,
            &SourceAwareParser,
            Some(41),
            Some(42),
            9,
            "/volume_0/Library/LaunchDaemons/example.plist",
            Vec::new(),
        )
        .expect("source-aware parser should receive compound primary input");

        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].json["artifact_id"], 41);
        assert_eq!(objects[0].json["system_file_id"], 42);
        assert_eq!(objects[0].json["fs_identifier"], 9);
        assert_eq!(objects[0].json["bytes"], json!([4, 5, 6]));
        assert_eq!(
            objects[0].json["path"],
            "/volume_0/Library/LaunchDaemons/example.plist"
        );
    }

    #[test]
    fn strips_one_numeric_apfs_volume_namespace() {
        assert_eq!(
            strip_apfs_volume_namespace("/volume_0/Users/alice/file"),
            Some("/Users/alice/file")
        );
        assert_eq!(
            strip_apfs_volume_namespace("/volume_12/private/var/db/file"),
            Some("/private/var/db/file")
        );
        assert_eq!(strip_apfs_volume_namespace("/Users/alice/file"), None);
        assert_eq!(strip_apfs_volume_namespace("/volume_x/Users/alice"), None);
        assert_eq!(strip_apfs_volume_namespace("/volume_/Users/alice"), None);
        assert_eq!(strip_apfs_volume_namespace("/volume_0"), None);
    }

    #[test]
    fn macos_catalog_pattern_matches_canonical_apfs_path() {
        let regex = regex::Regex::new(
            r"^/Users/[^/]+/Library/Preferences/com\.apple\.LaunchServices\.QuarantineEventsV2$",
        )
        .expect("valid catalog pattern");
        let stored =
            "/volume_0/Users/alice/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2";
        assert!(!regex.is_match(stored));
        assert!(
            strip_apfs_volume_namespace(stored).is_some_and(|path| regex.is_match(path)),
            "catalog matcher must also test the path without /volume_N"
        );
    }

    #[test]
    fn infers_root_spotlight_and_fsevents_paths_as_macos() {
        for path in [
            r"^/\.Spotlight-V100/Store-V2/[^/]+/store\.db$",
            r"^/\.fseventsd/.*$",
        ] {
            assert_eq!(
                infer_platform(&[ArtifactPath::WithFlag {
                    path: path.to_string(),
                    regexp: true,
                }]),
                "macOS"
            );
        }
    }

    #[test]
    fn macos_catalog_bindings_match_real_apfs_path_shapes() {
        let artifact_set = ArtifactSet::from_yaml_str(include_str!("../artifacts.yaml"))
            .expect("embedded artifacts.yaml should parse");
        let cases = [
            (
                "macos_launchd",
                "/volume_0/Users/alice/Library/LaunchAgents/example.plist",
            ),
            (
                "macos_launchd",
                "/volume_0/Library/Apple/System/Library/LaunchDaemons/example.plist",
            ),
            (
                "macos_loginwindow",
                "/volume_0/Users/alice/Library/Preferences/ByHost/com.apple.loginwindow.UUID.plist",
            ),
            (
                "macos_quarantine",
                "/volume_0/Users/alice/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
            ),
            (
                "macos_network",
                "/volume_0/Library/Preferences/SystemConfiguration/preferences.plist",
            ),
            (
                "macos_network",
                "/volume_0/Library/Preferences/com.apple.wifi.known-networks.plist",
            ),
            (
                "macos_network",
                "/volume_0/private/var/db/dhcpclient/leases/en0.plist",
            ),
            (
                "macos_spotlight",
                "/volume_0/.Spotlight-V100/Store-V2/UUID/store.db",
            ),
            (
                "macos_spotlight",
                "/volume_0/private/var/db/Spotlight-V100/BootVolume/Store-V2/UUID/store.db",
            ),
            (
                "macos_spotlight",
                "/volume_0/private/var/db/Spotlight-V100/Preboot/Store-V2/UUID/store.db",
            ),
            (
                "macos_app_bundle",
                "/volume_0/Applications/WhatsApp.app/Contents/Info.plist",
            ),
            (
                "macos_app_bundle",
                "/volume_0/Applications/Example.app/Contents/Helpers/Updater.app/Contents/Info.plist",
            ),
            (
                "macos_install_history",
                "/volume_0/Library/Receipts/InstallHistory.plist",
            ),
            (
                "macos_package_receipt",
                "/volume_0/private/var/db/receipts/com.example.application.plist",
            ),
            (
                "macos_container_registration",
                "/volume_0/Users/alice/Library/Containers/com.example.application/.com.apple.containermanagerd.metadata.plist",
            ),
        ];

        for (parser, stored_path) in cases {
            let canonical = strip_apfs_volume_namespace(stored_path);
            let matched = artifact_set.artifacts.iter().any(|artifact| {
                artifact.parser.as_deref() == Some(parser)
                    && artifact.paths.iter().any(|path| {
                        let regex = regex::Regex::new(&path.to_regex())
                            .expect("embedded artifact pattern should compile");
                        regex.is_match(stored_path)
                            || canonical.is_some_and(|path| regex.is_match(path))
                    })
            });
            assert!(matched, "{parser} did not match {stored_path}");
        }

        let duplicate_generation = "/volume_0/.Spotlight-V100/Store-V2/UUID/.store.db";
        let canonical = strip_apfs_volume_namespace(duplicate_generation);
        let parser_matched = artifact_set.artifacts.iter().any(|artifact| {
            artifact.parser.as_deref() == Some("macos_spotlight")
                && artifact.paths.iter().any(|path| {
                    let regex = regex::Regex::new(&path.to_regex())
                        .expect("embedded artifact pattern should compile");
                    regex.is_match(duplicate_generation)
                        || canonical.is_some_and(|path| regex.is_match(path))
                })
        });
        assert!(
            !parser_matched,
            ".store.db must not be parsed as a duplicate Spotlight generation"
        );
    }

    #[test]
    fn ios_installed_application_catalog_bindings_match_primary_sources_only() {
        let artifact_set = ArtifactSet::from_yaml_str(include_str!("../artifacts.yaml"))
            .expect("embedded artifacts.yaml should parse");
        let cases = [
            (
                "mobile_ios_app_manifest",
                "/filesystem1/Applications/Camera.app/Info.plist",
            ),
            (
                "mobile_ios_app_manifest",
                "/filesystem1/private/var/containers/Bundle/Application/C278E46A-69EF-4D34-8214-A7DCE5133F82/WhatsApp.app/Info.plist",
            ),
            (
                "mobile_ios_app_container",
                "/filesystem1/private/var/mobile/Containers/Data/Application/010990CE-E32E-4D9B-91FF-F77956F2B55F/.com.apple.mobile_container_manager.metadata.plist",
            ),
            (
                "mobile_ios_app_container",
                "/filesystem1/private/var/mobile/Containers/Shared/AppGroup/B544848F-91B6-47CC-8E50-9D43575046D1/.com.apple.mobile_container_manager.metadata.plist",
            ),
            (
                "mobile_ios_frontboard",
                "/filesystem1/private/var/mobile/Library/FrontBoard/applicationState.db",
            ),
            (
                "mobile_ios_iconstate",
                "/filesystem1/private/var/mobile/Library/SpringBoard/IconState.plist",
            ),
            (
                "mobile_ios_mobileinstallation_log",
                "/filesystem1/private/var/installd/Library/Logs/MobileInstallation/mobile_installation.log.0",
            ),
        ];

        for (parser, stored_path) in cases {
            let matched = artifact_set.artifacts.iter().any(|artifact| {
                artifact.parser.as_deref() == Some(parser)
                    && artifact.paths.iter().any(|path| {
                        regex::Regex::new(&path.to_regex())
                            .expect("embedded artifact pattern should compile")
                            .is_match(stored_path)
                    })
            });
            assert!(matched, "{parser} did not match {stored_path}");
        }

        let nested_watch = "/filesystem1/private/var/containers/Bundle/Application/C278E46A-69EF-4D34-8214-A7DCE5133F82/Spotify.app/Watch/Spotify Watch App.app/Info.plist";
        let nested_matched = artifact_set.artifacts.iter().any(|artifact| {
            artifact.parser.as_deref() == Some("mobile_ios_app_manifest")
                && artifact.paths.iter().any(|path| {
                    regex::Regex::new(&path.to_regex())
                        .expect("embedded artifact pattern should compile")
                        .is_match(nested_watch)
                })
        });
        assert!(
            !nested_matched,
            "nested Watch/extension manifests must not become primary installed applications"
        );

        for untrusted_nested_path in [
            "/filesystem1/private/var/mobile/Documents/Applications/Impostor.app/Info.plist",
            "/filesystem1/private/var/mobile/Documents/private/var/containers/Bundle/Application/C278E46A-69EF-4D34-8214-A7DCE5133F82/Impostor.app/Info.plist",
            "/filesystem1/tmp/private/var/mobile/Applications/C278E46A-69EF-4D34-8214-A7DCE5133F82/Impostor.app/Info.plist",
            "/filesystem1/private/var/containers/Bundle/Application/not-a-uuid/Impostor.app/Info.plist",
        ] {
            let matched = artifact_set.artifacts.iter().any(|artifact| {
                artifact.parser.as_deref() == Some("mobile_ios_app_manifest")
                    && artifact.paths.iter().any(|path| {
                        regex::Regex::new(&path.to_regex())
                            .expect("embedded artifact pattern should compile")
                            .is_match(untrusted_nested_path)
                    })
            });
            assert!(
                !matched,
                "nested untrusted path must not assert installed-app presence: {untrusted_nested_path}"
            );
        }
    }

    #[test]
    fn messages_attachment_candidates_expand_native_path_forms() {
        let source = "/volume_0/Users/alice/Library/Messages/chat.db";
        for (path, expected) in [
            (
                "~/Library/Messages/Attachments/aa/bb/photo.jpg",
                "/volume_0/Users/alice/Library/Messages/Attachments/aa/bb/photo.jpg",
            ),
            (
                "/Users/alice/Library/Messages/Attachments/aa/bb/photo.jpg",
                "/volume_0/Users/alice/Library/Messages/Attachments/aa/bb/photo.jpg",
            ),
            (
                "Attachments/aa/bb/photo.jpg",
                "/volume_0/Users/alice/Library/Messages/Attachments/aa/bb/photo.jpg",
            ),
            (
                "/volume_0/Users/alice/Library/Messages/Attachments/aa/bb/photo.jpg",
                "/volume_0/Users/alice/Library/Messages/Attachments/aa/bb/photo.jpg",
            ),
        ] {
            let candidates = attachment_path_candidates(Some(source), path)
                .expect("valid Messages path should produce candidates");
            assert_eq!(candidates.exact[0], expected, "path form: {path}");
        }

        let ios = attachment_path_candidates(
            Some("/volume_0/private/var/mobile/Library/SMS/sms.db"),
            "/var/mobile/Library/SMS/Attachments/aa/photo.jpg",
        )
        .expect("iOS absolute attachment path should produce candidates");
        assert!(ios.exact.contains(
            &"/volume_0/private/var/mobile/Library/SMS/Attachments/aa/photo.jpg".to_string()
        ));
    }

    #[test]
    fn whatsapp_attachment_candidates_are_group_container_scoped() {
        let candidates = attachment_path_candidates(
            Some(
                "/volume_0/Users/alice/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite",
            ),
            "Message/Media/example.jpg",
        )
        .expect("valid WhatsApp path should produce candidates");
        assert_eq!(
            candidates.exact[0],
            "/volume_0/Users/alice/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Message/Media/example.jpg"
        );
        assert_eq!(
            candidates.scoped_suffix,
            Some((
                "/volume_0/Users/alice/Library/Group Containers/group.net.whatsapp.WhatsApp.shared"
                    .to_string(),
                "Message/Media/example.jpg".to_string(),
            ))
        );
    }

    #[test]
    fn messages_filename_is_used_when_local_path_is_absent() {
        let object = json!({
            "attachment": {
                "filename": "~/Library/Messages/Attachments/aa/photo.jpg"
            }
        });
        assert_eq!(
            attachment_local_path(&object).as_deref(),
            Some("~/Library/Messages/Attachments/aa/photo.jpg")
        );
    }

    #[test]
    fn attachment_candidates_reject_parent_traversal() {
        assert!(attachment_path_candidates(
            Some("/volume_0/Users/alice/Library/Messages/chat.db"),
            "Attachments/../bob/photo.jpg",
        )
        .is_none());
    }

    #[tokio::test]
    async fn attachment_resolution_stays_with_source_user_and_refuses_ambiguity() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory SQLite should open");
        sqlx::query(
            r#"
            CREATE TABLE system_files (
                id INTEGER PRIMARY KEY,
                evidence_id INTEGER NOT NULL,
                partition_id INTEGER NOT NULL,
                identifier INTEGER NOT NULL,
                absolute_path TEXT NOT NULL,
                host_path TEXT,
                sig_mime TEXT,
                name TEXT,
                size INTEGER,
                is_dir INTEGER NOT NULL DEFAULT 0
            );
            "#,
        )
        .execute(&pool)
        .await
        .expect("test schema should be created");
        sqlx::query("CREATE INDEX idx_files_ev_path ON system_files(evidence_id, absolute_path)")
            .execute(&pool)
            .await
            .expect("attachment lookup index should be created");

        for (id, path) in [
            (
                1_i64,
                "/volume_0/Users/alice/Library/Messages/Attachments/aa/photo.jpg",
            ),
            (
                2_i64,
                "/volume_0/Users/bob/Library/Messages/Attachments/aa/photo.jpg",
            ),
            (
                3_i64,
                "/volume_0/Users/alice/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/archive-a/Message/Media/collision.jpg",
            ),
            (
                4_i64,
                "/volume_0/Users/alice/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/archive-b/Message/Media/collision.jpg",
            ),
        ] {
            sqlx::query(
                "INSERT INTO system_files (id, evidence_id, partition_id, identifier, absolute_path, name, size) VALUES (?, 7, 8, ?, ?, 'photo.jpg', 10)",
            )
            .bind(id)
            .bind(id + 100)
            .bind(path)
            .execute(&pool)
            .await
            .expect("test file should be inserted");
        }

        let mut tx = pool.begin().await.expect("transaction should begin");
        let resolved = resolve_attachment_file(
            &mut tx,
            7,
            8,
            Some("/volume_0/Users/alice/Library/Messages/chat.db"),
            "~/Library/Messages/Attachments/aa/photo.jpg",
        )
        .await
        .expect("Messages resolution should succeed")
        .expect("Alice's exact attachment should resolve");
        assert_eq!(resolved.id, 1);

        let basename_only = resolve_attachment_file(
            &mut tx,
            7,
            8,
            Some("/volume_0/Users/alice/Library/Messages/chat.db"),
            "photo.jpg",
        )
        .await
        .expect("basename lookup should not error");
        assert!(
            basename_only.is_none(),
            "a basename must not fall back across users"
        );

        let ambiguous = resolve_attachment_file(
            &mut tx,
            7,
            8,
            Some(
                "/volume_0/Users/alice/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/ChatStorage.sqlite",
            ),
            "Message/Media/collision.jpg",
        )
        .await
        .expect("ambiguous suffix lookup should not error");
        assert!(
            ambiguous.is_none(),
            "two scoped suffix matches must not be resolved arbitrarily"
        );
    }

    #[tokio::test]
    async fn attachment_resolution_batches_more_paths_than_one_query_chunk() {
        const FILE_COUNT: usize = 1_101;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory SQLite should open");
        sqlx::query(
            r#"
            CREATE TABLE system_files (
                id INTEGER PRIMARY KEY,
                evidence_id INTEGER NOT NULL,
                partition_id INTEGER NOT NULL,
                identifier INTEGER NOT NULL,
                absolute_path TEXT NOT NULL,
                host_path TEXT,
                sig_mime TEXT,
                name TEXT,
                size INTEGER,
                is_dir INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_files_ev_path
                ON system_files(evidence_id, absolute_path);
            "#,
        )
        .execute(&pool)
        .await
        .expect("test schema and attachment index should be created");

        let source =
            "/filesystem1/private/var/mobile/Containers/Shared/AppGroup/GROUP/ChatStorage.sqlite";
        let mut objects = Vec::with_capacity(FILE_COUNT + 1);
        let mut tx = pool.begin().await.expect("transaction should begin");
        for index in 0..FILE_COUNT {
            let relative_path = format!("Message/Media/photo-{index:04}.jpg");
            let absolute_path = format!(
                "/filesystem1/private/var/mobile/Containers/Shared/AppGroup/GROUP/{relative_path}"
            );
            sqlx::query(
                "INSERT INTO system_files (id, evidence_id, partition_id, identifier, absolute_path, name, size) VALUES (?, 7, 8, ?, ?, ?, 10)",
            )
            .bind(index as i64 + 1)
            .bind(index as i64 + 10_000)
            .bind(&absolute_path)
            .bind(format!("photo-{index:04}.jpg"))
            .execute(&mut *tx)
            .await
            .expect("test file should be inserted");

            objects.push(ObjectParsed {
                parser: "mobile_ios_whatsapp",
                kind: "mobile.communication.attachment",
                text: relative_path.clone(),
                json: json!({
                    "source": { "path": source },
                    "media": { "local_path": relative_path },
                }),
            });
        }
        objects.push(ObjectParsed {
            parser: "mobile_ios_whatsapp",
            kind: "mobile.communication.message",
            text: "not an attachment".to_string(),
            json: json!({}),
        });

        let resolved = resolve_attachment_files_batch(&mut tx, 7, 8, &objects)
            .await
            .expect("batched resolution should succeed");
        assert_eq!(resolved.len(), objects.len());
        assert_eq!(resolved.iter().flatten().count(), FILE_COUNT);
        assert_eq!(resolved[0].as_ref().map(|file| file.id), Some(1));
        assert_eq!(
            resolved[FILE_COUNT - 1].as_ref().map(|file| file.id),
            Some(FILE_COUNT as i64)
        );
        assert!(resolved[FILE_COUNT].is_none());
    }
}

pub async fn identify_artefacts(
    evidence_id: i64,
    partition_id: i64,
    pool: &SqlitePool,
    tx_progress: Option<Sender<IndexerEvent>>,
    artifacts_yaml_path: Option<&str>, // Allow injection or fallback to embedded
) {
    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Info,
            message: format!("Preparing artefact identification for partition {partition_id}…"),
        },
    )
    .await;

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

    let total_files = all_files.len() as u64;

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

    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Progress {
                current: 0,
                total: total_files,
            },
            message: format!(
                "Scanning {total_files} indexed files against {} artefact definitions…",
                compiled_artifacts.len()
            ),
        },
    )
    .await;

    // Now iterate over all files once and check against all artifacts. APFS
    // exposes each volume below `/volume_N`, while catalogue paths describe
    // native macOS paths such as `/Users/...` and `/Library/...`. Match both
    // representations but keep the indexed absolute path unchanged.
    let progress_interval = (total_files / 100).max(10_000);
    let mut matched_artefacts = 0u64;
    for (index, file) in all_files.iter().enumerate() {
        let logical_path = strip_apfs_volume_namespace(&file.absolute_path);
        for (artifact, regexes) in &compiled_artifacts {
            let mut matched = false;
            for rx in regexes {
                if rx.is_match(&file.absolute_path)
                    || logical_path.is_some_and(|path| rx.is_match(path))
                {
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
                } else {
                    matched_artefacts += 1;
                }
            }
        }

        let current = index as u64 + 1;
        if current % progress_interval == 0 || current == total_files {
            send_progress(
                &tx_progress,
                IndexerEvent {
                    evidence_id,
                    event_type: IndexerEventType::Progress {
                        current,
                        total: total_files,
                    },
                    message: format!(
                        "Identifying artefacts: {current}/{total_files} files scanned, \
                         {matched_artefacts} matches found…"
                    ),
                },
            )
            .await;
        }
    }

    send_progress(
        &tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::Success,
            message: format!(
                "Artefact identification complete: scanned {total_files} files and found \
                 {matched_artefacts} matches."
            ),
        },
    )
    .await;
}

/// Remove Exhume's synthetic APFS volume namespace from an indexed path.
///
/// `/volume_0/Users/alice/file` becomes `/Users/alice/file`. Paths from other
/// filesystems, and malformed/non-numeric volume prefixes, are left alone.
fn strip_apfs_volume_namespace(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/volume_")?;
    let slash = rest.find('/')?;
    let index = &rest[..slash];
    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(&rest[slash..])
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

    if parser.companion_specs().is_empty() && !parser.requires_source_metadata() {
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

const ATTACHMENT_EXACT_PATH_BATCH_SIZE: usize = 500;

#[derive(Debug, Clone)]
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
    resolved: Option<&ResolvedAttachmentFile>,
) -> Result<()> {
    let local_path = attachment_local_path(object_json);
    let kind = json_string(object_json, &["attachment", "kind"]);
    let is_location = kind.as_deref() == Some("location");

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
    .bind(resolved.map(|file| file.id))
    .bind(resolved.map(|file| file.identifier))
    .bind(resolved.map(|file| file.absolute_path.clone()))
    .bind(resolved.and_then(|file| file.host_path.clone()))
    .bind(resolved.and_then(|file| file.sig_mime.clone()))
    .bind(resolved.and_then(|file| file.name.clone()))
    .bind(resolved.and_then(|file| file.size))
    .bind(json_string(object_json, &["preview", "mime"]))
    .bind(json_string(object_json, &["preview", "data"]))
    .bind(object_json.to_string())
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Resolve every attachment emitted by one parser invocation in a bounded
/// number of indexed queries. The result vector is positionally aligned with
/// `objects`; non-attachment objects and attachments without usable paths are
/// represented by `None`.
async fn resolve_attachment_files_batch(
    tx: &mut Transaction<'_, Sqlite>,
    evidence_id: i64,
    partition_id: i64,
    objects: &[ObjectParsed],
) -> Result<Vec<Option<ResolvedAttachmentFile>>> {
    let candidates = objects
        .iter()
        .map(|object| {
            if object.kind != "mobile.communication.attachment" {
                return None;
            }
            let source_path = json_string(&object.json, &["source", "path"]);
            let local_path = attachment_local_path(&object.json);
            attachment_path_candidates(source_path.as_deref(), local_path.as_deref()?)
        })
        .collect::<Vec<_>>();

    resolve_attachment_candidates_batch(tx, evidence_id, partition_id, &candidates).await
}

async fn resolve_attachment_candidates_batch(
    tx: &mut Transaction<'_, Sqlite>,
    evidence_id: i64,
    partition_id: i64,
    candidates: &[Option<AttachmentPathCandidates>],
) -> Result<Vec<Option<ResolvedAttachmentFile>>> {
    let mut seen_paths = HashSet::new();
    let mut exact_paths = Vec::new();
    for candidate_set in candidates.iter().flatten() {
        for path in &candidate_set.exact {
            if seen_paths.insert(path.clone()) {
                exact_paths.push(path.clone());
            }
        }
    }

    let mut exact_files = HashMap::<String, ResolvedAttachmentFile>::new();
    for path_batch in exact_paths.chunks(ATTACHMENT_EXACT_PATH_BATCH_SIZE) {
        let mut query = sqlx::QueryBuilder::<Sqlite>::new(
            r#"
            SELECT
                id,
                identifier,
                absolute_path,
                host_path,
                sig_mime,
                name,
                size
            FROM system_files INDEXED BY idx_files_ev_path
            WHERE evidence_id = "#,
        );
        query
            .push_bind(evidence_id)
            .push(" AND partition_id = ")
            .push_bind(partition_id)
            .push(
                r#"
              AND is_dir = 0
              AND absolute_path IN ("#,
            );
        {
            let mut separated = query.separated(", ");
            for path in path_batch {
                separated.push_bind(path);
            }
        }
        query.push(") ORDER BY id;");

        for row in query.build().fetch_all(&mut **tx).await? {
            let file = decode_resolved_attachment_row(&row)?;
            exact_files
                .entry(file.absolute_path.clone())
                .or_insert(file);
        }
    }

    let mut resolved = Vec::with_capacity(candidates.len());
    let mut suffixes_by_scope = HashMap::<String, HashSet<String>>::new();
    for candidate_set in candidates {
        let Some(candidate_set) = candidate_set else {
            resolved.push(None);
            continue;
        };

        if let Some(file) = candidate_set
            .exact
            .iter()
            .find_map(|path| exact_files.get(path))
        {
            resolved.push(Some(file.clone()));
            continue;
        }

        if let Some((scope, suffix)) = candidate_set.scoped_suffix.as_ref() {
            suffixes_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(suffix.clone());
        }
        resolved.push(None);
    }

    let mut suffix_matches = HashMap::<(String, String), Vec<ResolvedAttachmentFile>>::new();
    for (scope, suffixes) in suffixes_by_scope {
        let lower_bound = format!("{}/", scope.trim_end_matches('/'));
        // Evidence paths are normalized with `/` separators. Incrementing the
        // trailing slash gives the exclusive upper bound for every descendant
        // while retaining an indexable range predicate.
        let upper_bound = format!("{}0", scope.trim_end_matches('/'));
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                identifier,
                absolute_path,
                host_path,
                sig_mime,
                name,
                size
            FROM system_files INDEXED BY idx_files_ev_path
            WHERE evidence_id = ?
              AND partition_id = ?
              AND is_dir = 0
              AND absolute_path >= ?
              AND absolute_path < ?
            ORDER BY id;
            "#,
        )
        .bind(evidence_id)
        .bind(partition_id)
        .bind(lower_bound)
        .bind(upper_bound)
        .fetch_all(&mut **tx)
        .await?;

        for row in rows {
            let file = decode_resolved_attachment_row(&row)?;
            let Some(suffix) = stable_attachment_suffix(&file.absolute_path) else {
                continue;
            };
            if suffixes.contains(suffix) {
                suffix_matches
                    .entry((scope.clone(), suffix.to_string()))
                    .or_default()
                    .push(file);
            }
        }
    }

    for (index, candidate_set) in candidates.iter().enumerate() {
        if resolved[index].is_some() {
            continue;
        }
        let Some((scope, suffix)) = candidate_set
            .as_ref()
            .and_then(|candidate_set| candidate_set.scoped_suffix.as_ref())
        else {
            continue;
        };
        if let Some([file]) = suffix_matches
            .get(&(scope.clone(), suffix.clone()))
            .map(Vec::as_slice)
        {
            resolved[index] = Some(file.clone());
        }
    }

    Ok(resolved)
}

#[cfg(test)]
async fn resolve_attachment_file(
    tx: &mut Transaction<'_, Sqlite>,
    evidence_id: i64,
    partition_id: i64,
    source_path: Option<&str>,
    local_path: &str,
) -> Result<Option<ResolvedAttachmentFile>> {
    let Some(paths) = attachment_path_candidates(source_path, local_path) else {
        return Ok(None);
    };
    resolve_attachment_candidates_batch(tx, evidence_id, partition_id, &[Some(paths)])
        .await
        .map(|mut resolved| resolved.pop().flatten())
}

fn decode_resolved_attachment_row(row: &sqlx::sqlite::SqliteRow) -> Result<ResolvedAttachmentFile> {
    Ok(ResolvedAttachmentFile {
        id: row.try_get("id")?,
        identifier: row.try_get("identifier")?,
        absolute_path: row.try_get("absolute_path")?,
        host_path: row.try_get("host_path")?,
        sig_mime: row.try_get("sig_mime")?,
        name: row.try_get("name")?,
        size: row.try_get("size")?,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct AttachmentPathCandidates {
    exact: Vec<String>,
    /// `(source scope, stable relative suffix)` used only when it identifies a
    /// single file. The scope is always the source database's directory.
    scoped_suffix: Option<(String, String)>,
}

fn attachment_local_path(object_json: &Value) -> Option<String> {
    json_string(object_json, &["media", "local_path"])
        .or_else(|| json_string(object_json, &["attachment", "local_path"]))
        // Apple Messages calls this column `filename`; it commonly contains a
        // full `~/Library/Messages/Attachments/...` path rather than a basename.
        .or_else(|| json_string(object_json, &["attachment", "filename"]))
}

fn attachment_path_candidates(
    source_path: Option<&str>,
    local_path: &str,
) -> Option<AttachmentPathCandidates> {
    let source = normalize_evidence_path(source_path?)?;
    let local = normalize_evidence_path(local_path)?;
    let source_dir = source.rsplit_once('/')?.0.to_string();
    let volume_prefix = apfs_volume_prefix(&source);
    let home = source_home(&source);
    let mut exact = Vec::new();

    if local.starts_with("/volume_") {
        push_unique(&mut exact, local.clone());
    } else if local.starts_with('/') {
        if let Some(prefix) = volume_prefix {
            push_unique(&mut exact, format!("{prefix}{local}"));
            if local.starts_with("/var/mobile/") {
                push_unique(&mut exact, format!("{prefix}/private{local}"));
            }
        } else if local.starts_with("/var/mobile/") {
            push_unique(&mut exact, format!("/private{local}"));
        }
        push_unique(&mut exact, local.clone());
    } else if let Some(rest) = local.strip_prefix("~/") {
        if let Some(home) = &home {
            push_unique(&mut exact, format!("{home}/{rest}"));
        }
    } else {
        // WhatsApp paths are normally `Message/Media/...`; Messages paths may
        // be `Attachments/...`. Both are relative to the source DB directory.
        push_unique(&mut exact, format!("{source_dir}/{local}"));

        if !local.starts_with("Message/") {
            push_unique(&mut exact, format!("{source_dir}/Message/{local}"));
        }
        if local.starts_with("Library/") {
            if let Some(home) = &home {
                push_unique(&mut exact, format!("{home}/{local}"));
            }
        }
    }

    let scoped_suffix =
        stable_attachment_suffix(&local).map(|suffix| (source_dir, suffix.to_string()));
    (!exact.is_empty()).then_some(AttachmentPathCandidates {
        exact,
        scoped_suffix,
    })
}

fn normalize_evidence_path(path: &str) -> Option<String> {
    let mut path = path.trim().trim_end_matches('\0').replace('\\', "/");
    if let Some(file_path) = path.strip_prefix("file://") {
        path = file_path.to_string();
    }
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    if path.is_empty()
        || path
            .split('/')
            .any(|component| component == "." || component == "..")
    {
        return None;
    }
    Some(path)
}

fn apfs_volume_prefix(path: &str) -> Option<&str> {
    let logical = strip_apfs_volume_namespace(path)?;
    Some(&path[..path.len() - logical.len()])
}

fn source_home(path: &str) -> Option<String> {
    let volume_prefix = apfs_volume_prefix(path).unwrap_or_default();
    let logical = strip_apfs_volume_namespace(path).unwrap_or(path);
    if let Some(rest) = logical.strip_prefix("/Users/") {
        let user = rest.split('/').next()?;
        return Some(format!("{volume_prefix}/Users/{user}"));
    }
    for mobile_home in ["/private/var/mobile", "/var/mobile"] {
        if logical == mobile_home || logical.starts_with(&format!("{mobile_home}/")) {
            return Some(format!("{volume_prefix}{mobile_home}"));
        }
    }
    None
}

fn stable_attachment_suffix(path: &str) -> Option<&str> {
    let path = path.strip_prefix("~/").unwrap_or(path);
    for marker in ["Library/Messages/", "Library/SMS/"] {
        if let Some(index) = path.find(marker) {
            let suffix = &path[index + marker.len()..];
            return suffix.starts_with("Attachments/").then_some(suffix);
        }
    }
    for marker in ["Message/Media/", "Attachments/"] {
        if let Some(index) = path.find(marker) {
            let suffix = &path[index..];
            return (suffix.len() > marker.len()).then_some(suffix);
        }
    }
    None
}

fn push_unique(paths: &mut Vec<String>, path: String) {
    if !paths.iter().any(|candidate| candidate == &path) {
        paths.push(path);
    }
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

#[derive(Debug, Default)]
struct ParserRunStats {
    files: u64,
    failures: u64,
    objects_emitted: u64,
    elapsed_ms: u128,
}

#[allow(clippy::too_many_arguments)]
async fn send_parser_progress(
    tx_progress: &Option<Sender<IndexerEvent>>,
    evidence_id: i64,
    current: u64,
    total: u64,
    parser: &str,
    file_path: &str,
    artifact_id: i64,
    file_id: Option<i64>,
    phase: ParserProgressPhase,
    elapsed_ms: Option<u64>,
    setup_ms: Option<u64>,
    parse_ms: Option<u64>,
    persistence_ms: Option<u64>,
    objects_emitted: Option<u64>,
    message: String,
) {
    send_progress(
        tx_progress,
        IndexerEvent {
            evidence_id,
            event_type: IndexerEventType::ParserProgress {
                current,
                total,
                parser: parser.to_string(),
                file_path: file_path.to_string(),
                artifact_id,
                file_id,
                phase,
                elapsed_ms,
                setup_ms,
                parse_ms,
                persistence_ms,
                objects_emitted,
            },
            message,
        },
    )
    .await;
}

fn elapsed_millis(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
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
    let mut parser_stats = BTreeMap::<String, ParserRunStats>::new();

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

        let parser_started_at = Instant::now();
        parser_stats
            .entry(parser_name.to_string())
            .or_default()
            .files += 1;
        let start_message =
            format!("Running parser {parser_name} ({processed_files}/{total}): {abs_path}");
        send_parser_progress(
            &tx_progress,
            evidence_id,
            processed_files,
            total,
            parser_name,
            &abs_path,
            artifact_id,
            file_id,
            ParserProgressPhase::Started,
            None,
            None,
            None,
            None,
            None,
            start_message,
        )
        .await;
        info!(
            "artefact_parser_start evidence_id={evidence_id} partition_id={partition_id} \
             parser={parser_name} position={processed_files}/{total} artifact_id={artifact_id} \
             file_id={file_id:?} path={abs_path:?}"
        );

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
                let elapsed_ms = elapsed_millis(parser_started_at);
                if let Some(stats) = parser_stats.get_mut(parser_name) {
                    stats.failures += 1;
                    stats.elapsed_ms += u128::from(elapsed_ms);
                }
                let msg = format!(
                    "Failed to resolve parser companions (parser={}, file={}): {e:?}",
                    parser_name, abs_path
                );
                send_parser_progress(
                    &tx_progress,
                    evidence_id,
                    processed_files,
                    total,
                    parser_name,
                    &abs_path,
                    artifact_id,
                    file_id,
                    ParserProgressPhase::Failed,
                    Some(elapsed_ms),
                    Some(elapsed_ms),
                    None,
                    None,
                    Some(0),
                    msg.clone(),
                )
                .await;
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

        let setup_ms = elapsed_millis(parser_started_at);
        let parser_call_started_at = Instant::now();

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
                let parse_ms = elapsed_millis(parser_call_started_at);
                let elapsed_ms = elapsed_millis(parser_started_at);
                if let Some(stats) = parser_stats.get_mut(parser_name) {
                    stats.failures += 1;
                    stats.elapsed_ms += u128::from(elapsed_ms);
                }
                let msg = format!(
                    "Extraction failed (parser={}, file={}): {e:?}",
                    parser_name, abs_path
                );
                send_parser_progress(
                    &tx_progress,
                    evidence_id,
                    processed_files,
                    total,
                    parser_name,
                    &abs_path,
                    artifact_id,
                    file_id,
                    ParserProgressPhase::Failed,
                    Some(elapsed_ms),
                    Some(setup_ms),
                    Some(parse_ms),
                    None,
                    Some(0),
                    msg.clone(),
                )
                .await;
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

        let parse_ms = elapsed_millis(parser_call_started_at);
        let objects_from_file = objs.len() as u64;
        let persistence_started_at = Instant::now();

        let attachment_count = objs
            .iter()
            .filter(|object| object.kind == "mobile.communication.attachment")
            .count();
        let attachment_resolution_started_at = Instant::now();
        let attachment_resolutions = if attachment_count == 0 {
            vec![None; objs.len()]
        } else {
            match resolve_attachment_files_batch(&mut tx, evidence_id, partition_id, &objs).await {
                Ok(resolved) => {
                    let resolved_count = resolved.iter().flatten().count();
                    info!(
                        "artefact_attachment_resolution evidence_id={evidence_id} \
                         partition_id={partition_id} parser={parser_name} \
                         attachments={attachment_count} resolved={resolved_count} \
                         elapsed_ms={}",
                        elapsed_millis(attachment_resolution_started_at)
                    );
                    resolved
                }
                Err(e) => {
                    let msg = format!(
                        "Attachment path resolution failed (parser={parser_name}, file={abs_path}): {e:?}"
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
                    vec![None; objs.len()]
                }
            }
        };

        for (obj, resolved_attachment) in objs.into_iter().zip(attachment_resolutions.iter()) {
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
                    resolved_attachment.as_ref(),
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

        let persistence_ms = elapsed_millis(persistence_started_at);
        let elapsed_ms = elapsed_millis(parser_started_at);
        if let Some(stats) = parser_stats.get_mut(parser_name) {
            stats.objects_emitted += objects_from_file;
            stats.elapsed_ms += u128::from(elapsed_ms);
        }
        let completed_message = format!(
            "Parser {parser_name} completed ({processed_files}/{total}) in {elapsed_ms} ms \
             (setup {setup_ms} ms, parse {parse_ms} ms, database {persistence_ms} ms); \
             {objects_from_file} objects: {abs_path}"
        );
        send_parser_progress(
            &tx_progress,
            evidence_id,
            processed_files,
            total,
            parser_name,
            &abs_path,
            artifact_id,
            file_id,
            ParserProgressPhase::Completed,
            Some(elapsed_ms),
            Some(setup_ms),
            Some(parse_ms),
            Some(persistence_ms),
            Some(objects_from_file),
            completed_message,
        )
        .await;
        info!(
            "artefact_parser_finish evidence_id={evidence_id} partition_id={partition_id} \
             parser={parser_name} position={processed_files}/{total} artifact_id={artifact_id} \
             file_id={file_id:?} elapsed_ms={elapsed_ms} setup_ms={setup_ms} \
             parse_ms={parse_ms} persistence_ms={persistence_ms} \
             objects_emitted={objects_from_file} \
             path={abs_path:?}"
        );

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
    for (parser, stats) in parser_stats {
        info!(
            "artefact_parser_summary evidence_id={evidence_id} partition_id={partition_id} \
             parser={parser} files={} failures={} objects_emitted={} elapsed_ms={}",
            stats.files, stats.failures, stats.objects_emitted, stats.elapsed_ms
        );
    }
}
