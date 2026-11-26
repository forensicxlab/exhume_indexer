//! Scoped, bounded evidence reads and staged parser input, shared by recipes.
use super::*;
use exhume_artefacts::{CompoundParserInput, ParserFileProvider, ParserSource};
use exhume_filesystem::filesystem::FsFileReadSeek;
use std::{
    io::{Read, Write},
    path::PathBuf,
};
use zeroize::Zeroizing;
pub(super) fn source_row(row: &sqlx::sqlite::SqliteRow, role: &str) -> Result<RecoverySource> {
    Ok(RecoverySource {
        role: role.into(),
        path: row.try_get("absolute_path")?,
        system_file_id: row.try_get("id")?,
        fs_identifier: u64::try_from(row.try_get::<i64, _>("identifier")?)
            .context("negative filesystem identifier")?,
        size_bytes: u64::try_from(row.try_get::<i64, _>("size")?)
            .context("negative evidence file size")?,
        sha256: None,
        record_offsets: Vec::new(),
    })
}

pub(super) async fn find(
    pool: &SqlitePool,
    job: &RecoveryJob,
    path: &str,
    role: &str,
) -> Result<Option<RecoverySource>> {
    let query = if job.platform == RecoveryPlatform::Windows {
        // NTFS inventories retain native backslashes; extracted folders use
        // slashes. Compare both representations without changing provenance.
        "SELECT id,identifier,absolute_path,size FROM system_files WHERE evidence_id=? AND partition_id=? AND is_dir=0 AND lower(replace(absolute_path,char(92),'/'))=lower(replace(?,char(92),'/')) ORDER BY id LIMIT 2"
    } else {
        "SELECT id,identifier,absolute_path,size FROM system_files WHERE evidence_id=? AND partition_id=? AND is_dir=0 AND absolute_path=? ORDER BY id LIMIT 2"
    };
    let rows = sqlx::query(query)
        .bind(job.scope.evidence_id)
        .bind(job.scope.partition_id)
        .bind(path)
        .fetch_all(pool)
        .await?;
    if rows.len() > 1 {
        return Err(blocked(
            RecoveryStatus::MissingEvidence,
            "ambiguous_dependency",
        ));
    }
    rows.first().map(|r| source_row(r, role)).transpose()
}

pub(crate) fn copy_source<F: Filesystem>(
    fs: &mut F,
    source: &mut RecoverySource,
    output: &mut dyn Write,
    maximum: u64,
    cancel: Option<&AtomicBool>,
) -> Result<()>
where
    F::FileType: FileCommon,
{
    blocking(|| copy_source_inner(fs, source, output, maximum, cancel))
}
fn copy_source_inner<F: Filesystem>(
    fs: &mut F,
    source: &mut RecoverySource,
    output: &mut dyn Write,
    maximum: u64,
    cancel: Option<&AtomicBool>,
) -> Result<()>
where
    F::FileType: FileCommon,
{
    check_cancel(cancel)?;
    if source.size_bytes > maximum {
        return Err(blocked(RecoveryStatus::LimitExceeded, "input_byte_limit"));
    }
    let record = fs
        .get_file(source.fs_identifier)
        .or_else(|_| fs.get_file_by_path(&source.path, source.fs_identifier))
        .map_err(|_| blocked(RecoveryStatus::FileRead, "source_open_failed"))?;
    if record.size() != source.size_bytes {
        return Err(blocked(
            RecoveryStatus::FileRead,
            "source_changed_since_inventory",
        ));
    }
    let mut reader = FsFileReadSeek::new(fs, record);
    let mut buffer = Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut total = 0u64;
    let mut digest = Sha256::new();
    loop {
        check_cancel(cancel)?;
        let count = reader
            .read(&mut buffer)
            .map_err(|_| blocked(RecoveryStatus::FileRead, "source_read_failed"))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count)?)
            .context("source size overflow")?;
        if total > maximum {
            return Err(blocked(RecoveryStatus::LimitExceeded, "input_byte_limit"));
        }
        output
            .write_all(&buffer[..count])
            .context("failed to stage acquired recovery input")?;
        digest.update(&buffer[..count]);
    }
    if total != source.size_bytes {
        return Err(blocked(
            RecoveryStatus::FileRead,
            "source_changed_since_inventory",
        ));
    }
    source.sha256 = Some(hex::encode(digest.finalize()));
    Ok(())
}

pub(super) fn read_source<F: Filesystem>(
    fs: &mut F,
    source: &mut RecoverySource,
    maximum: u64,
    cancel: Option<&AtomicBool>,
) -> Result<Zeroizing<Vec<u8>>>
where
    F::FileType: FileCommon,
{
    let mut bytes = Zeroizing::new(Vec::new());
    copy_source(fs, source, &mut *bytes, maximum, cancel)?;
    Ok(bytes)
}
pub(super) async fn read_dependency<F: Filesystem>(
    pool: &SqlitePool,
    fs: &mut F,
    job: &mut RecoveryJob,
    path: &str,
    role: &str,
    maximum: u64,
    cancel: Option<&AtomicBool>,
) -> Result<Option<Zeroizing<Vec<u8>>>>
where
    F::FileType: FileCommon,
{
    let Some(mut source) = find(pool, job, path, role).await? else {
        return Ok(None);
    };
    let result = read_source(fs, &mut source, maximum, cancel);
    if let Some(existing) = job
        .sources
        .iter_mut()
        .find(|s| s.role == source.role && s.system_file_id == source.system_file_id)
    {
        *existing = source;
    } else {
        job.sources.push(source);
    }
    result.map(Some)
}

pub(super) struct StagedInput<'a> {
    files: Vec<(ParserSource, PathBuf)>,
    cancel: Option<&'a AtomicBool>,
    _directory: tempfile::TempDir,
}

impl StagedInput<'_> {
    /// Construct thread-local parser adapters only for the synchronous parse.
    /// The async job retains sendable staged-file descriptors across awaits.
    pub(super) fn with_input<T>(self, operation: impl FnOnce(ParserInput<'_>) -> T) -> T {
        let primary = self.files[0].0.clone();
        let companions = self.files.iter().skip(1).map(|(s, _)| s.clone()).collect();
        operation(ParserInput::Compound(CompoundParserInput {
            primary,
            companions,
            provider: Box::new(StagedProvider {
                files: self.files,
                cancel: self.cancel,
            }),
        }))
    }
}
struct StagedProvider<'a> {
    files: Vec<(ParserSource, PathBuf)>,
    cancel: Option<&'a AtomicBool>,
}
impl ParserFileProvider for StagedProvider<'_> {
    fn copy_to(&mut self, source: &ParserSource, writer: &mut dyn Write) -> Result<()> {
        let (_, path) = self
            .files
            .iter()
            .find(|(s, _)| {
                s.role == source.role
                    && s.original_path == source.original_path
                    && s.fs_identifier == source.fs_identifier
            })
            .context("unknown staged recovery source")?;
        let mut reader = std::fs::File::open(path)?;
        let mut buffer = vec![0; 64 * 1024];
        loop {
            check_cancel(self.cancel)?;
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            writer.write_all(&buffer[..count])?;
        }
        Ok(())
    }
}
pub(super) async fn stage_input<'a, F: Filesystem>(
    pool: &SqlitePool,
    fs: &mut F,
    job: &mut RecoveryJob,
    specs: &[exhume_artefacts::CompanionSpec],
    maximum: u64,
    cancel: Option<&'a AtomicBool>,
) -> Result<StagedInput<'a>>
where
    F::FileType: FileCommon,
{
    let directory = tempfile::tempdir()?;
    let mut sources = vec![job
        .sources
        .first()
        .context("recovery primary source missing")?
        .clone()];
    for spec in specs {
        use exhume_artefacts::CompanionPathRule;
        let path = match spec.path_rule {
            CompanionPathRule::Suffix(suffix) => format!("{}{suffix}", job.primary_path),
            CompanionPathRule::Sibling(name) => format!(
                "{}{name}",
                job.primary_path
                    .rsplit_once('/')
                    .map_or("", |(dir, _)| &job.primary_path[..dir.len() + 1])
            ),
            CompanionPathRule::Extension(extension) => std::path::Path::new(&job.primary_path)
                .with_extension(extension)
                .to_string_lossy()
                .into_owned(),
        };
        if let Some(source) = find(pool, job, &path, spec.role).await? {
            sources.push(source);
        } else if spec.required {
            return Err(blocked(
                RecoveryStatus::MissingEvidence,
                "required_companion_missing",
            ));
        }
    }
    let mut files = Vec::new();
    for (index, source) in sources.iter_mut().enumerate() {
        let path = directory.path().join(format!("input-{index}"));
        copy_source(
            fs,
            source,
            &mut std::fs::File::create(&path)?,
            maximum,
            cancel,
        )?;
        files.push((
            ParserSource::new(
                &source.role,
                &source.path,
                (index == 0).then_some(job.artifact_id),
                Some(source.system_file_id),
                Some(source.fs_identifier),
            ),
            path,
        ));
    }
    *job.sources
        .first_mut()
        .context("recovery primary source missing")? = sources.remove(0);
    job.sources.extend(sources);
    Ok(StagedInput {
        files,
        cancel,
        _directory: directory,
    })
}
