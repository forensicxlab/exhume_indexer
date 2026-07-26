# exhume_indexer

Filesystem indexing and artefact extraction for Exhume.

`exhume_indexer` indexes a folder or filesystem partition into an Exhume SQLite
database. It can also run file-signature identification, match configured
artefact paths, execute parsers from `exhume_artefacts`, and populate timeline
and attachment-reference tables for downstream investigation workflows.

## Install

```bash
cargo install exhume_indexer
```

From the Exhume workspace, run the binary with:

```bash
cargo run -p exhume_indexer -- --help
```

## CLI usage

Index a folder:

```bash
exhume_indexer \
  --body /path/to/folder \
  --database /path/to/exhume.sqlite \
  --no-progress
```

Index a filesystem partition inside a disk image:

```bash
exhume_indexer \
  --body /path/to/disk.raw \
  --format raw \
  --offset 0x100000 \
  --size 0x400000 \
  --database /path/to/exhume.sqlite
```

Run the optional post-indexing passes:

```bash
exhume_indexer \
  --body /path/to/folder \
  --database /path/to/exhume.sqlite \
  --identify-files \
  --extract-artefacts \
  --no-progress
```

Useful options:

- `--body`: folder, disk image, or body to index.
- `--database`: SQLite database path. If omitted, defaults to `<body>.sqlite`
  next to the source.
- `--format`: disk image/body format (`raw`, `ewf`, or `auto`).
- `--offset`: filesystem start offset in bytes. Required for disk images.
- `--size`: filesystem size in sectors. Required for disk images.
- `--evidence-id`: evidence identifier to store in SQLite. Defaults to `1`.
- `--partition-id`: reuse or upsert an existing partition row.
- `--fvek`: BitLocker Full Volume Encryption Key as hex.
- `--identify-files`: classify indexed files by file signature.
- `--extract-artefacts`: match configured artefacts and run available parsers.
- `--artifacts-yaml`: override the embedded artefact catalog with a custom YAML
  file.
- `--no-progress`: disable interactive progress bars and print plain messages.
- `--log-level`: `error`, `warn`, `info`, `debug`, or `trace`.

## Database output

The crate creates and updates the core Exhume tables needed by the desktop app
and other consumers:

- `evidence` and `partitions` for source metadata.
- `system_files` for indexed filesystem entries.
- `artifact_files` and `artifact_objects` for matched and parsed artefacts.
- `timeline_events` for filesystem and parser-derived timeline events.
- `artifact_attachment_refs` for parsed mobile attachments and resolved backing
  files.

The embedded artefact catalog is available as `ARTIFACTS_YAML`; it can be parsed
with `ArtifactSet::from_yaml_str` or replaced at runtime with `--artifacts-yaml`.

## Library usage

Most integrations use the high-level async entry points:

- `ensure_tables`
- `ensure_evidence_row`
- `insert_partition`, `update_partition`, `get_partition`, `list_partitions`
- `index_folder`
- `index_partition_with_format`
- `identify_file_types`
- `identify_artefacts`
- `extract_artefacts`
- `populate_filesystem_timeline`

Example:

```rust
use exhume_indexer::{ensure_evidence_row, ensure_tables, index_folder};
use sqlx::sqlite::SqlitePool;

async fn index_case(pool: &SqlitePool) -> Result<(), Box<dyn std::error::Error>> {
    ensure_tables(pool).await?;
    ensure_evidence_row(pool, 1, "/evidence/folder", true).await?;
    index_folder(1, 1, "/evidence/folder".to_string(), pool, None, None).await;
    Ok(())
}
```

## Artefact extraction

`--extract-artefacts` loads the embedded `artifacts.yaml` catalog by default,
matches indexed paths, and runs parser names declared by catalog entries. Parser
companion-file declarations are resolved against indexed `system_files`, allowing
mobile SQLite parsers to consume WAL/SHM sidecars or sibling databases when
present.

When extraction runs, parser-derived events are written to `timeline_events`.
Filesystem timestamp events can be refreshed with `populate_filesystem_timeline`.
