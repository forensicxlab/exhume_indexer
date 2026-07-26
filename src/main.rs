use anyhow::{Context, Result};
use clap::{crate_authors, crate_version, value_parser, Arg, ArgAction, Command};
use clap_num::maybe_hex;
use exhume_artefacts::parsers::build_registry;
use exhume_body::Body;
use exhume_filesystem::detected_fs::{detect_filesystem, detect_filesystem_from_path, KeyMaterial};
use exhume_indexer::artifacts::{extract_artefacts, identify_artefacts};
use exhume_indexer::identification::identify_file_types;
use exhume_indexer::{
    ensure_evidence_row, ensure_tables, index_folder, index_partition_with_format,
    insert_partition, populate_filesystem_timeline, update_partition, IndexerEvent,
    IndexerEventType, PartitionKind,
};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("exhume_indexer")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Index a filesystem partition into an Exhume SQLite database.")
        .arg(
            Arg::new("body")
                .short('b')
                .long("body")
                .value_parser(value_parser!(String))
                .required(true)
                .help("The path to the disk image, body, or folder to index."),
        )
        .arg(
            Arg::new("database")
                .short('d')
                .long("database")
                .value_parser(value_parser!(String))
                .help("The SQLite database path used for the index. Defaults to <body>.sqlite next to the source."),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(value_parser!(String))
                .required(false)
                .help("The body format, either 'raw', 'ewf', or 'auto'."),
        )
        .arg(
            Arg::new("offset")
                .short('o')
                .long("offset")
                .value_parser(maybe_hex::<u64>)
                .required(false)
                .help("Partition start offset in bytes (decimal or hex). Required for disk images."),
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_parser(maybe_hex::<u64>)
                .required(false)
                .help("Partition size in sectors (decimal or hex). Required for disk images."),
        )
        .arg(
            Arg::new("evidence_id")
                .long("evidence-id")
                .value_parser(value_parser!(i64))
                .default_value("1")
                .help("Evidence identifier stored in the SQLite index."),
        )
        .arg(
            Arg::new("partition_id")
                .long("partition-id")
                .value_parser(value_parser!(i64))
                .help("Existing partition identifier to reuse. If omitted, a logical partition row is created."),
        )
        .arg(
            Arg::new("fvek")
                .long("fvek")
                .value_parser(value_parser!(String))
                .help("BitLocker Full Volume Encryption Key (hex)."),
        )
        .arg(
            Arg::new("identify_files")
                .long("identify-files")
                .action(ArgAction::SetTrue)
                .help("Run the file-signature identification pass after indexing."),
        )
        .arg(
            Arg::new("extract_artefacts")
                .long("extract-artefacts")
                .action(ArgAction::SetTrue)
                .help("Identify configured artefacts and run artefact parsers after indexing."),
        )
        .arg(
            Arg::new("artifacts_yaml")
                .long("artifacts-yaml")
                .value_parser(value_parser!(String))
                .help("Optional path to a custom artifacts.yaml file."),
        )
        .arg(
            Arg::new("no_progress")
                .long("no-progress")
                .action(ArgAction::SetTrue)
                .help("Disable interactive progress bars and print plain progress messages."),
        )
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log-level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info")
                .help("Set the log verbosity level."),
        )
        .get_matches();

    let log_level = matches
        .get_one::<String>("log_level")
        .expect("defaulted by clap");
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level.clone())),
        )
        .init();

    let body_path = matches
        .get_one::<String>("body")
        .expect("required by clap")
        .to_owned();
    let is_directory = Path::new(&body_path).is_dir();
    let database_path = matches
        .get_one::<String>("database")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_database_path(&body_path));
    let format = matches
        .get_one::<String>("format")
        .map(String::as_str)
        .unwrap_or("auto");
    let evidence_id = *matches
        .get_one::<i64>("evidence_id")
        .expect("defaulted by clap");
    let first_byte_addr = matches.get_one::<u64>("offset").copied().unwrap_or(0);
    let size_sectors = matches.get_one::<u64>("size").copied().unwrap_or(0);
    let run_identify_files = matches.get_flag("identify_files");
    let run_extract_artefacts = matches.get_flag("extract_artefacts");
    let progress_enabled = !matches.get_flag("no_progress") && std::io::stderr().is_terminal();
    let artifacts_yaml_path = matches
        .get_one::<String>("artifacts_yaml")
        .map(String::as_str);
    let detected_sector_size = if is_directory {
        0
    } else {
        Body::new(body_path.clone(), format).get_sector_size() as u64
    };

    if !is_directory
        && (matches.get_one::<u64>("offset").is_none() || matches.get_one::<u64>("size").is_none())
    {
        anyhow::bail!("--offset and --size are required when indexing a disk image or body");
    }

    if is_directory {
        if matches.get_one::<String>("fvek").is_some() {
            anyhow::bail!("--fvek is only supported when indexing a disk image partition");
        }
        if matches.get_one::<String>("format").is_some() {
            eprintln!("[WARNING] --format is ignored when indexing a folder");
        }
    }

    let pool = open_pool(&database_path).await?;
    ensure_tables(&pool).await?;
    ensure_evidence_row(&pool, evidence_id, &body_path, is_directory).await?;

    let partition_id = match matches.get_one::<i64>("partition_id").copied() {
        Some(id) => {
            upsert_logical_partition(
                &pool,
                evidence_id,
                id,
                first_byte_addr,
                size_sectors,
                detected_sector_size,
            )
            .await?;
            id
        }
        None => {
            insert_logical_partition(
                &pool,
                evidence_id,
                first_byte_addr,
                size_sectors,
                detected_sector_size,
            )
            .await?
        }
    };

    if let Some(fvek_hex) = matches.get_one::<String>("fvek") {
        let _ = hex::decode(fvek_hex).context("Provided FVEK is not valid hex")?;
        sqlx::query("UPDATE partitions SET fvek = ? WHERE id = ?")
            .bind(fvek_hex)
            .bind(partition_id)
            .execute(&pool)
            .await
            .context("Failed to store FVEK in partitions")?;
    }

    let (tx, rx) = mpsc::channel::<IndexerEvent>(100);
    let monitor = tokio::spawn(progress_monitor(rx, progress_enabled));

    let index_result = if is_directory {
        index_folder(
            evidence_id,
            partition_id,
            body_path.clone(),
            &pool,
            Some(tx.clone()),
            None,
        )
        .await;
        Ok(())
    } else {
        index_partition_with_format(
            evidence_id,
            partition_id,
            size_sectors,
            first_byte_addr,
            body_path.clone(),
            format,
            &pool,
            Some(tx.clone()),
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))
    };

    drop(tx);
    let _ = monitor.await;
    index_result?;

    if run_identify_files || run_extract_artefacts {
        let mut fs = reopen_input(
            &body_path,
            format,
            is_directory,
            first_byte_addr,
            size_sectors,
            matches.get_one::<String>("fvek").map(String::as_str),
        )?;

        if run_identify_files {
            let (tx, rx) = mpsc::channel::<IndexerEvent>(100);
            let monitor = tokio::spawn(progress_monitor(rx, progress_enabled));
            identify_file_types(&mut fs, evidence_id, partition_id, &pool, Some(tx.clone())).await;
            drop(tx);
            let _ = monitor.await;
        }

        if run_extract_artefacts {
            let registry = build_registry();

            let (tx1, rx1) = mpsc::channel::<IndexerEvent>(100);
            let monitor1 = tokio::spawn(progress_monitor(rx1, progress_enabled));
            identify_artefacts(
                evidence_id,
                partition_id,
                &pool,
                Some(tx1.clone()),
                artifacts_yaml_path,
            )
            .await;
            drop(tx1);
            let _ = monitor1.await;

            let (tx2, rx2) = mpsc::channel::<IndexerEvent>(100);
            let monitor2 = tokio::spawn(progress_monitor(rx2, progress_enabled));
            extract_artefacts(
                evidence_id,
                partition_id,
                &pool,
                &mut fs,
                &registry,
                Some(tx2.clone()),
                None,
            )
            .await;
            drop(tx2);
            let _ = monitor2.await;

            populate_filesystem_timeline(evidence_id, partition_id, &pool)
                .await
                .context("Failed to populate filesystem timeline")?;
        }
    }

    Ok(())
}

fn default_database_path(body_path: &str) -> PathBuf {
    let path = Path::new(body_path);
    let file_name = path.file_name().unwrap_or_else(|| path.as_os_str());
    let mut database_name = OsString::from(file_name);
    database_name.push(".sqlite");

    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.join(&database_name))
        .unwrap_or_else(|| PathBuf::from(database_name))
}

async fn open_pool(path: &Path) -> Result<SqlitePool> {
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

    SqlitePoolOptions::new()
        .max_connections(1)
        .idle_timeout(Duration::from_secs(60))
        .connect_with(opts)
        .await
        .context("Failed to open SQLite database")
}

async fn insert_logical_partition(
    pool: &SqlitePool,
    evidence_id: i64,
    first_byte_addr: u64,
    size_sectors: u64,
    sector_size: u64,
) -> Result<i64> {
    insert_partition(
        pool,
        evidence_id,
        PartitionKind::Logical,
        first_byte_addr,
        size_sectors,
        sector_size,
        size_sectors.saturating_mul(sector_size),
        None,
    )
    .await
    .context("Failed to insert logical partition row")
}

async fn upsert_logical_partition(
    pool: &SqlitePool,
    evidence_id: i64,
    partition_id: i64,
    first_byte_addr: u64,
    size_sectors: u64,
    sector_size: u64,
) -> Result<()> {
    let size_bytes = size_sectors.saturating_mul(sector_size);
    let updated = update_partition(
        pool,
        partition_id,
        first_byte_addr,
        size_sectors,
        sector_size,
        size_bytes,
    )
    .await
    .context("Failed to update logical partition row")?;

    if !updated {
        sqlx::query(
            r#"
            INSERT INTO partitions (
                id, evidence_id, kind, first_byte_addr, size_sectors, sector_size, size_bytes
            ) VALUES (?, ?, 'logical', ?, ?, ?, ?)
            "#,
        )
        .bind(partition_id)
        .bind(evidence_id)
        .bind(first_byte_addr as i64)
        .bind(size_sectors as i64)
        .bind(sector_size as i64)
        .bind(size_bytes as i64)
        .execute(pool)
        .await
        .context("Failed to insert logical partition row with the requested id")?;
    }

    Ok(())
}

fn reopen_input(
    body_path: &str,
    format: &str,
    is_directory: bool,
    first_byte_addr: u64,
    size_sectors: u64,
    fvek_hex: Option<&str>,
) -> Result<impl exhume_filesystem::Filesystem> {
    if is_directory {
        return detect_filesystem_from_path(body_path).map_err(|e| anyhow::anyhow!(e.to_string()));
    }

    let mut body = Body::new(body_path.to_owned(), format);
    let sector_size = body.get_sector_size() as u64;
    let partition_size_bytes = size_sectors * sector_size;
    let key_material = parse_key_material(fvek_hex)?;

    detect_filesystem(
        &mut body,
        first_byte_addr,
        partition_size_bytes,
        key_material,
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}

fn parse_key_material(fvek_hex: Option<&str>) -> Result<Option<KeyMaterial>> {
    match fvek_hex {
        Some(hex_str) => Ok(Some(KeyMaterial {
            bitlocker_fvek: Some(hex::decode(hex_str).context("Provided FVEK is not valid hex")?),
        })),
        None => Ok(None),
    }
}

async fn progress_monitor(mut rx: mpsc::Receiver<IndexerEvent>, progress_enabled: bool) {
    if !progress_enabled {
        plain_progress_monitor(&mut rx).await;
        return;
    }

    let multi = MultiProgress::new();
    let bar = multi.add(ProgressBar::new_spinner());
    bar.set_style(spinner_style());
    bar.enable_steady_tick(Duration::from_millis(120));

    while let Some(event) = rx.recv().await {
        match event.event_type {
            IndexerEventType::Info => {
                bar.set_style(spinner_style());
                bar.set_message(event.message);
            }
            IndexerEventType::Progress { current, total } => {
                if total == 0 {
                    bar.set_style(spinner_style());
                    bar.set_message(event.message);
                } else {
                    if bar.length() != Some(total) {
                        bar.set_style(progress_style());
                        bar.set_length(total);
                    }
                    bar.set_position(current.min(total));
                    bar.set_message(event.message);
                }
            }
            IndexerEventType::Success => {
                bar.finish_with_message(event.message);
            }
            IndexerEventType::Warning => {
                bar.println(format!("[WARNING] {}", event.message));
            }
            IndexerEventType::Error => {
                bar.abandon_with_message(event.message);
            }
        }
    }

    if !bar.is_finished() {
        bar.finish_and_clear();
    }
}

async fn plain_progress_monitor(rx: &mut mpsc::Receiver<IndexerEvent>) {
    while let Some(event) = rx.recv().await {
        match event.event_type {
            IndexerEventType::Info => eprintln!("[INFO] {}", event.message),
            IndexerEventType::Progress { current, total } => {
                eprintln!("[PROGRESS] {current}/{total} {}", event.message)
            }
            IndexerEventType::Success => eprintln!("[SUCCESS] {}", event.message),
            IndexerEventType::Warning => eprintln!("[WARNING] {}", event.message),
            IndexerEventType::Error => eprintln!("[ERROR] {}", event.message),
        }
    }
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.cyan} {msg}").expect("spinner template should be valid")
}

fn progress_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
    )
    .expect("progress template should be valid")
    .progress_chars("=> ")
}
