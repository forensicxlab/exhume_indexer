//! On-demand, verified media recovery. The acquired file reference stays intact;
//! this catalogue describes separate derived files, not filesystem inventory rows.
use crate::recovery::{RecoveryJob, RecoveryScope, RecoverySource};
use exhume_artefacts::{
    assets::{
        self as media, AssetErrorCode as DecodeErrorCode, AssetRecipe, DumpedAsset, Rendition,
    },
    parsers::ParserRegistry,
    ObjectParsed,
};
use exhume_filesystem::{filesystem::FileCommon, Filesystem};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::{
    fs::File,
    io::{Seek, SeekFrom},
    path::{Component, Path},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssetErrorCode {
    StaleReference,
    MissingEvidence,
    InvalidMetadata,
    Unsupported,
    AuthenticationFailed,
    ValidationFailed,
    LimitExceeded,
    Cancelled,
    FileRead,
    CacheIo,
    Database,
    UnsafeDestination,
}
#[derive(Debug)]
pub struct AssetError {
    pub code: AssetErrorCode,
}
impl std::fmt::Display for AssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.code {
            AssetErrorCode::StaleReference => {
                "This attachment is no longer in the published inventory. Refresh the conversation."
            }
            AssetErrorCode::MissingEvidence => {
                "The acquired attachment file is missing or ambiguous."
            }
            AssetErrorCode::InvalidMetadata => {
                "Attachment recovery metadata or its local key is missing or malformed."
            }
            AssetErrorCode::Unsupported => "This attachment encryption version is unsupported.",
            AssetErrorCode::AuthenticationFailed => {
                "The acquired attachment failed authentication."
            }
            AssetErrorCode::ValidationFailed => {
                "The attachment failed size or plaintext hash validation."
            }
            AssetErrorCode::LimitExceeded => "The attachment or cache exceeds the recovery limit.",
            AssetErrorCode::Cancelled => "Attachment recovery cancelled.",
            AssetErrorCode::FileRead => "The acquired attachment could not be read.",
            AssetErrorCode::CacheIo => "The derived asset cache is unavailable.",
            AssetErrorCode::Database => "The asset catalogue is unavailable.",
            AssetErrorCode::UnsafeDestination => {
                "The derived asset directory overlaps source evidence or is unsafe."
            }
        })
    }
}
impl std::error::Error for AssetError {}
type Result<T> = std::result::Result<T, AssetError>;
fn failed(code: AssetErrorCode) -> AssetError {
    AssetError { code }
}
impl From<sqlx::Error> for AssetError {
    fn from(_: sqlx::Error) -> Self {
        failed(AssetErrorCode::Database)
    }
}
impl From<std::io::Error> for AssetError {
    fn from(_: std::io::Error) -> Self {
        failed(AssetErrorCode::CacheIo)
    }
}
impl From<media::AssetError> for AssetError {
    fn from(e: media::AssetError) -> Self {
        failed(match e.code {
            DecodeErrorCode::MissingMetadata | DecodeErrorCode::InvalidKey => {
                AssetErrorCode::InvalidMetadata
            }
            DecodeErrorCode::UnsupportedVersion => AssetErrorCode::Unsupported,
            DecodeErrorCode::AuthenticationFailed => AssetErrorCode::AuthenticationFailed,
            DecodeErrorCode::Malformed
            | DecodeErrorCode::SizeMismatch
            | DecodeErrorCode::HashMismatch => AssetErrorCode::ValidationFailed,
            DecodeErrorCode::LimitExceeded => AssetErrorCode::LimitExceeded,
            DecodeErrorCode::Cancelled => AssetErrorCode::Cancelled,
            DecodeErrorCode::Io => AssetErrorCode::CacheIo,
            DecodeErrorCode::UnsafeDestination => AssetErrorCode::UnsafeDestination,
        })
    }
}
fn check(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
        Err(failed(AssetErrorCode::Cancelled))
    } else {
        Ok(())
    }
}

/// Independent media limits; the JSON record-spool limit does not limit media.
#[derive(Debug, Clone)]
pub struct AssetLimits {
    pub file_bytes: u64,
    pub cache_bytes: u64,
    pub cache_files: usize,
}
impl Default for AssetLimits {
    fn default() -> Self {
        Self {
            file_bytes: 1024 * 1024 * 1024,
            cache_bytes: 10 * 1024 * 1024 * 1024,
            cache_files: 10000,
        }
    }
}

#[derive(Debug)]
pub struct PreparedAsset {
    pub generation: String,
    pub scope: RecoveryScope,
    pub reference_id: i64,
    pub target_id: String,
    pub inventory_run_id: Option<i64>,
    pub asset_id: String,
    pub source: RecoverySource,
    pub rendition: Rendition,
    spec: Box<dyn AssetRecipe>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRecord {
    pub generation: String,
    pub asset_id: String,
    pub scope: RecoveryScope,
    pub target_id: String,
    pub inventory_run_id: Option<i64>,
    pub source: RecoverySource,
    pub rendition: Rendition,
    pub mime: Option<String>,
    pub output: DumpedAsset,
}
pub struct OpenedAsset {
    pub record: AssetRecord,
    pub file: File,
    pub cache_hit: bool,
}

pub async fn ensure_schema(pool: &SqlitePool) -> std::result::Result<(), sqlx::Error> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let columns = sqlx::query("PRAGMA table_info(artifact_assets)")
        .fetch_all(&mut *tx)
        .await?;
    if !columns.is_empty()
        && !columns
            .iter()
            .any(|row| row.get::<String, _>("name") == "target_id")
    {
        return Err(sqlx::Error::Protocol(
            "unsupported asset catalogue schema; rebuild the derived index".into(),
        ));
    }
    for statement in r#"
    CREATE TABLE IF NOT EXISTS artifact_asset_state(id INTEGER PRIMARY KEY CHECK(id=1),generation TEXT NOT NULL);
    INSERT OR IGNORE INTO artifact_asset_state(id,generation) VALUES(1,lower(hex(randomblob(16))));
    CREATE TABLE IF NOT EXISTS artifact_assets(asset_id TEXT PRIMARY KEY,evidence_id INTEGER NOT NULL,partition_id INTEGER NOT NULL,target_id TEXT NOT NULL,status TEXT NOT NULL,details_json TEXT NOT NULL,updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')));
    CREATE INDEX IF NOT EXISTS idx_artifact_assets_scope ON artifact_assets(evidence_id,partition_id,target_id);
"#.split(';').filter(|statement|!statement.trim().is_empty()) {
    sqlx::query(statement).execute(&mut *tx).await?;
}
    tx.commit().await?;
    Ok(())
}
/// Changes when an analysis DB is rebuilt, even if SQLite rowids are reused.
pub async fn asset_generation(pool: &SqlitePool) -> Result<String> {
    ensure_schema(pool).await?;
    Ok(
        sqlx::query_scalar("SELECT generation FROM artifact_asset_state WHERE id=1")
            .fetch_one(pool)
            .await?,
    )
}

/// Resolve by a scoped reference ID, never by a renderer-supplied path or key.
/// The parser supplies a recipe; the publication resolver enforces its source scope.
pub async fn prepare_asset(
    pool: &SqlitePool,
    registry: &ParserRegistry,
    scope: RecoveryScope,
    reference_id: i64,
    rendition: Rendition,
) -> Result<PreparedAsset> {
    let generation = asset_generation(pool).await?;
    if scope.evidence_id <= 0 || scope.partition_id <= 0 || reference_id <= 0 {
        return Err(failed(AssetErrorCode::StaleReference));
    }
    let row=sqlx::query("SELECT r.json,o.parser,o.artifact_id,sf.absolute_path FROM artifact_attachment_refs r JOIN artifact_objects o ON o.id=r.artifact_object_id AND o.evidence_id=r.evidence_id AND o.partition_id=r.partition_id AND o.parser=r.parser JOIN artifacts a ON a.id=o.artifact_id AND a.evidence_id=o.evidence_id AND a.partition_id=o.partition_id AND a.parser=o.parser JOIN system_files sf ON sf.id=a.file_id AND sf.evidence_id=a.evidence_id AND sf.partition_id=a.partition_id WHERE r.evidence_id=? AND r.partition_id=? AND r.id=? LIMIT 1")
        .bind(scope.evidence_id).bind(scope.partition_id).bind(reference_id).fetch_optional(pool).await?
        .ok_or_else(||failed(AssetErrorCode::StaleReference))?;
    let parser_id: String = row.try_get("parser")?;
    let parser = registry
        .get(parser_id.as_str())
        .ok_or_else(|| failed(AssetErrorCode::Unsupported))?;
    let primary_path: String = row.try_get("absolute_path")?;
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT run_id FROM index_inventory WHERE evidence_id=? AND partition_id=?",
    )
    .bind(scope.evidence_id)
    .bind(scope.partition_id)
    .fetch_optional(pool)
    .await?;
    let target_id = crate::recovery::scoped_id(
        "recovery-target-",
        scope,
        current,
        &format!("{parser_id}:{primary_path}"),
    );
    if crate::recovery::manages_parser(&parser_id) {
        let json:Option<String>=sqlx::query_scalar("SELECT details_json FROM recovery_jobs WHERE evidence_id=? AND partition_id=? AND target_id=? AND artifact_id=?")
            .bind(scope.evidence_id).bind(scope.partition_id).bind(&target_id).bind(row.get::<i64,_>("artifact_id")).fetch_optional(pool).await?;
        let job: RecoveryJob =
            serde_json::from_str(&json.ok_or_else(|| failed(AssetErrorCode::StaleReference))?)
                .map_err(|_| failed(AssetErrorCode::InvalidMetadata))?;
        if job.scope != scope
            || job.published_attempt_id.is_none()
            || job.inventory_run_id != current
        {
            return Err(failed(AssetErrorCode::StaleReference));
        }
    }
    let mut record: serde_json::Value = serde_json::from_str(row.try_get("json")?)
        .map_err(|_| failed(AssetErrorCode::InvalidMetadata))?;
    if record["source"]["path"].as_str() != Some(primary_path.as_str()) {
        return Err(failed(AssetErrorCode::StaleReference));
    }
    let spec = parser
        .attachment_recipe(&record, rendition)?
        .ok_or_else(|| failed(AssetErrorCode::Unsupported))?;
    let local_path = recipe_path(&**parser, &primary_path, &*spec)?;
    record["media"]["local_path"] = local_path.clone().into();
    record["attachment"]["local_path"] = local_path.into();
    let mut tx = pool.begin().await?;
    let resolved = crate::artifacts::resolve_attachment_files_batch(
        &mut tx,
        scope.evidence_id,
        scope.partition_id,
        &[ObjectParsed {
            parser: parser.name(),
            kind: "mobile.communication.attachment",
            text: String::new(),
            json: record,
        }],
    )
    .await
    .map_err(|_| failed(AssetErrorCode::Database))?;
    tx.commit().await?;
    let source = resolved
        .into_iter()
        .next()
        .flatten()
        .ok_or_else(|| failed(AssetErrorCode::MissingEvidence))?;
    let source = RecoverySource {
        role: match rendition {
            Rendition::Original => "attachment",
            Rendition::Thumbnail => "attachment_thumbnail",
        }
        .into(),
        path: source.absolute_path,
        system_file_id: source.id,
        fs_identifier: u64::try_from(source.identifier)
            .map_err(|_| failed(AssetErrorCode::InvalidMetadata))?,
        size_bytes: source
            .size
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(|| failed(AssetErrorCode::InvalidMetadata))?,
        sha256: None,
        record_offsets: Vec::new(),
    };
    let identity = serde_json::json!([
        "indexed-asset-v2",
        generation,
        scope,
        target_id,
        current,
        source.system_file_id,
        source.fs_identifier,
        source.path,
        source.size_bytes,
        spec.fingerprint(),
        rendition
    ]);
    let asset_id = format!(
        "asset-{}",
        hex::encode(Sha256::digest(identity.to_string().as_bytes()))
    );
    Ok(PreparedAsset {
        generation,
        scope,
        reference_id,
        target_id,
        inventory_run_id: current,
        asset_id,
        source,
        rendition,
        spec,
    })
}

/// Cache access does not require reopening the source image or its credentials.
/// The published reference/recipe is still validated before a cached file opens.
pub async fn open_cached_asset(
    pool: &SqlitePool,
    prepared: &PreparedAsset,
    directory: &Path,
    cancel: Option<&AtomicBool>,
) -> Result<Option<OpenedAsset>> {
    check(cancel)?;
    ensure_schema(pool).await?;
    let json:Option<String>=sqlx::query_scalar("SELECT details_json FROM artifact_assets WHERE asset_id=? AND evidence_id=? AND partition_id=? AND status='ready'")
        .bind(&prepared.asset_id).bind(prepared.scope.evidence_id).bind(prepared.scope.partition_id).fetch_optional(pool).await?;
    let Some(json) = json else { return Ok(None) };
    let record: AssetRecord =
        serde_json::from_str(&json).map_err(|_| failed(AssetErrorCode::InvalidMetadata))?;
    if record.generation != prepared.generation
        || record.asset_id != prepared.asset_id
        || record.scope != prepared.scope
        || record.target_id != prepared.target_id
        || record.inventory_run_id != prepared.inventory_run_id
        || record.source.system_file_id != prepared.source.system_file_id
        || record.rendition != prepared.rendition
    {
        return Err(failed(AssetErrorCode::StaleReference));
    }
    match crate::recovery::blocking(|| media::open_dumped_asset(directory, &record.output, cancel))
    {
        Ok(file) => Ok(Some(OpenedAsset {
            record,
            file,
            cache_hit: true,
        })),
        Err(error) if error.code == DecodeErrorCode::Cancelled => Err(error.into()),
        Err(_) => Ok(None),
    }
}

/// Recover a single requested asset. Callers provide the already scoped
/// filesystem and an output directory outside acquired folder evidence.
pub async fn recover_asset<F: Filesystem>(
    pool: &SqlitePool,
    registry: &ParserRegistry,
    fs: &mut F,
    mut prepared: PreparedAsset,
    directory: &Path,
    limits: &AssetLimits,
    cancel: Option<&AtomicBool>,
) -> Result<OpenedAsset>
where
    F::FileType: FileCommon,
{
    if let Some(asset) = open_cached_asset(pool, &prepared, directory, cancel).await? {
        return Ok(asset);
    }
    let result = crate::recovery::blocking(|| -> Result<DumpedAsset> {
        check(cancel)?;
        if limits.file_bytes == 0
            || limits.cache_bytes == 0
            || limits.cache_files == 0
            || prepared.source.size_bytes > limits.file_bytes
        {
            return Err(failed(AssetErrorCode::LimitExceeded));
        }
        media::create_dump_directory(directory)?;
        let mut used = 0u64;
        let mut files = 0usize;
        for entry in std::fs::read_dir(directory)? {
            check(cancel)?;
            let entry = entry?;
            let metadata = entry.metadata()?;
            files = files
                .checked_add(1)
                .ok_or_else(|| failed(AssetErrorCode::LimitExceeded))?;
            used = used
                .checked_add(metadata.len())
                .ok_or_else(|| failed(AssetErrorCode::LimitExceeded))?;
            if files >= limits.cache_files || used > limits.cache_bytes {
                return Err(failed(AssetErrorCode::LimitExceeded));
            }
        }
        let available = limits.cache_bytes.saturating_sub(used);
        if prepared
            .spec
            .plaintext_size()
            .unwrap_or(prepared.source.size_bytes)
            > available
        {
            return Err(failed(AssetErrorCode::LimitExceeded));
        }
        let mut staged = tempfile::Builder::new()
            .prefix(".cipher-")
            .tempfile_in(directory)?;
        crate::recovery::evidence::copy_source(
            fs,
            &mut prepared.source,
            staged.as_file_mut(),
            limits.file_bytes,
            cancel,
        )
        .map_err(|_| {
            if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                failed(AssetErrorCode::Cancelled)
            } else {
                failed(AssetErrorCode::FileRead)
            }
        })?;
        staged.as_file_mut().seek(SeekFrom::Start(0))?;
        let maximum = limits.file_bytes;
        crate::recovery::blocking(|| {
            media::dump_asset(
                staged.as_file_mut(),
                &*prepared.spec,
                directory,
                maximum,
                cancel,
            )
        })
        .map_err(Into::into)
    });
    let output = match result {
        Ok(output) => output,
        Err(error) => {
            let details = serde_json::json!({"reference_id":prepared.reference_id,"source":prepared.source,"rendition":prepared.rendition,"reason":error.code});
            save(pool, &prepared, "failed", &details.to_string()).await?;
            return Err(error);
        }
    };
    let record = AssetRecord {
        generation: prepared.generation.clone(),
        asset_id: prepared.asset_id.clone(),
        scope: prepared.scope,
        target_id: prepared.target_id.clone(),
        inventory_run_id: prepared.inventory_run_id,
        source: prepared.source.clone(),
        rendition: prepared.rendition,
        mime: prepared.spec.mime().map(str::to_owned),
        output,
    };
    let publication = async {
        check(cancel)?;
        let current = prepare_asset(
            pool,
            registry,
            prepared.scope,
            prepared.reference_id,
            prepared.rendition,
        )
        .await?;
        if current.asset_id != prepared.asset_id {
            return Err(failed(AssetErrorCode::StaleReference));
        }
        let json =
            serde_json::to_string(&record).map_err(|_| failed(AssetErrorCode::InvalidMetadata))?;
        save(pool, &prepared, "ready", &json).await
    }
    .await;
    if let Err(error) = publication {
        let _ = std::fs::remove_file(directory.join(&record.output.relative_path));
        return Err(error);
    }
    let file =
        crate::recovery::blocking(|| media::open_dumped_asset(directory, &record.output, cancel))?;
    Ok(OpenedAsset {
        record,
        file,
        cache_hit: false,
    })
}
async fn save(pool: &SqlitePool, p: &PreparedAsset, status: &str, json: &str) -> Result<()> {
    sqlx::query("INSERT INTO artifact_assets(asset_id,evidence_id,partition_id,target_id,status,details_json) VALUES(?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET status=excluded.status,details_json=excluded.details_json,updated_at=strftime('%s','now')")
        .bind(&p.asset_id).bind(p.scope.evidence_id).bind(p.scope.partition_id).bind(&p.target_id).bind(status).bind(json).execute(pool).await?;
    Ok(())
}

/// Expand only a parser-declared asset base. This is logical evidence-path
/// handling: it never canonicalizes an acquired path against the host OS.
fn recipe_path(
    parser: &dyn exhume_artefacts::Parser,
    primary: &str,
    recipe: &dyn AssetRecipe,
) -> Result<String> {
    let Some(base) = recipe.base_directory() else {
        return Ok(recipe.local_path().into());
    };
    let base = Path::new(base);
    if base.components().count() == 0
        || base
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(failed(AssetErrorCode::InvalidMetadata));
    }
    let primary = primary.replace('\\', "/");
    let root = parser
        .asset_root(Path::new(&primary))
        .ok_or_else(|| failed(AssetErrorCode::InvalidMetadata))?
        .join(base);
    let recorded = recipe.local_path().replace('\\', "/");
    let recorded = Path::new(&recorded);
    if recorded.components().any(|part| {
        matches!(
            part,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(failed(AssetErrorCode::InvalidMetadata));
    }
    let path = if recorded.is_absolute() {
        recorded.to_path_buf()
    } else {
        root.join(recorded)
    };
    if !path.starts_with(&root) || path == root {
        return Err(failed(AssetErrorCode::InvalidMetadata));
    }
    path.into_os_string()
        .into_string()
        .map_err(|_| failed(AssetErrorCode::InvalidMetadata))
}
