use anyhow::{Context, Result};
use clap::{crate_authors, crate_version, value_parser, Arg, ArgAction, Command};
use clap_num::maybe_hex;
use exhume_artefacts::parsers::build_registry;
use exhume_body::{credentials, Body, BodyOpenOptions};
use exhume_filesystem::detected_fs::{detect_filesystem, detect_filesystem_from_path, KeyMaterial};
use exhume_indexer::artifacts::identify_artefacts;
use exhume_indexer::recovery::{self, RecoveryReport, RecoveryScope, RecoverySession};
mod cli;
use cli::recovery as recovery_cli;
use exhume_indexer::identification::identify_file_types;
use exhume_indexer::{
    ensure_evidence_row, ensure_tables, index_folder_with_report,
    index_partition_with_options_report, insert_partition, populate_filesystem_timeline,
    update_partition, IndexerEvent, IndexerEventType, PartitionKind,
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
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(code) => std::process::ExitCode::from(code),
        Err(error) => {
            eprintln!("exhume_indexer: {error:#}");
            std::process::ExitCode::from(1)
        }
    }
}

async fn run() -> Result<u8> {
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, cancel.clone())?;
    #[cfg(unix)]
    signal_hook::flag::register(signal_hook::consts::SIGTERM, cancel.clone())?;
    let command = Command::new("exhume_indexer")
        .version(crate_version!())
        .arg(Arg::new("json_report").long("json-report").action(ArgAction::SetTrue).help("Print the final index run and coverage report as JSON."))
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
                .help("Disable interactive progress bars and log progress at the configured verbosity."),
        )
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log-level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info")
                .help("Set the log verbosity level."),
        )
        ;
    let matches = password_args(recovery_cli::arguments(command)).get_matches();
    let recovery_options = recovery_cli::RecoveryCli::from_matches(&matches)?;
    let mut recovery_session = RecoverySession::default();
    recovery_options.load_secrets(&mut recovery_session)?;
    let mut recovery_report = RecoveryReport::default();
    let mut retry_fvek = None;

    let log_level = matches
        .get_one::<String>("log_level")
        .expect("defaulted by clap");
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
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
    let mut first_byte_addr = matches.get_one::<u64>("offset").copied().unwrap_or(0);
    let mut size_sectors = matches.get_one::<u64>("size").copied().unwrap_or(0);
    let run_identify_files = matches.get_flag("identify_files");
    let run_extract_artefacts = matches.get_flag("extract_artefacts");
    let progress_enabled = !matches.get_flag("no_progress") && std::io::stderr().is_terminal();
    let artifacts_yaml_path = matches
        .get_one::<String>("artifacts_yaml")
        .map(String::as_str);
    let body_options = credentials::read_open_options(
        &body_path,
        format,
        matches
            .get_one::<String>("password_file")
            .map(String::as_str),
        matches.get_flag("password_stdin"),
    )
    .map_err(anyhow::Error::msg)?;
    let detected_sector_size = if is_directory {
        0
    } else {
        Body::open(body_path.clone(), format, &body_options)?.get_sector_size() as u64
    };

    if !is_directory
        && !recovery_options.retry
        && (matches.get_one::<u64>("offset").is_none() || matches.get_one::<u64>("size").is_none())
    {
        anyhow::bail!("--offset and --size are required when indexing a disk image or body");
    }

    if is_directory {
        if matches.get_one::<String>("fvek").is_some() {
            anyhow::bail!("--fvek is only supported when indexing a disk image partition");
        }
        if matches.get_one::<String>("format").is_some() {
            log::warn!("--format is ignored when indexing a folder");
        }
    }

    let pool = open_pool(&database_path).await?;
    ensure_tables(&pool).await?;
    if recovery_options.retry {
        let registered: Option<(String, String)> =
            sqlx::query_as("SELECT path,type FROM evidence WHERE id=?")
                .bind(evidence_id)
                .fetch_optional(&pool)
                .await?;
        let (registered, kind) =
            registered.context("retry requires an existing evidence registration")?;
        anyhow::ensure!(
            kind.eq_ignore_ascii_case("Folder") == is_directory,
            "retry input kind differs from the registered evidence"
        );
        anyhow::ensure!(
            std::fs::canonicalize(&registered)? == std::fs::canonicalize(&body_path)?,
            "retry source differs from the registered evidence"
        );
    } else {
        ensure_evidence_row(&pool, evidence_id, &body_path, is_directory).await?;
    }

    let partition_id = match matches.get_one::<i64>("partition_id").copied() {
        Some(id) => {
            if recovery_options.retry {
                let partition = exhume_indexer::get_partition(&pool, id)
                    .await?
                    .context("retry partition is missing")?;
                anyhow::ensure!(
                    partition.evidence_id == evidence_id,
                    "retry partition belongs to another evidence"
                );
                retry_fvek = partition.fvek;
                first_byte_addr = partition.first_byte_addr;
                size_sectors = partition.size_sectors;
            } else {
                upsert_logical_partition(
                    &pool,
                    evidence_id,
                    id,
                    first_byte_addr,
                    size_sectors,
                    detected_sector_size,
                )
                .await?;
            }
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

    let index_result = if recovery_options.retry {
        exhume_indexer::latest_inventory_report(&pool, evidence_id, partition_id)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
            .context("retry requires a published file inventory")
    } else if is_directory {
        index_folder_with_report(
            evidence_id,
            partition_id,
            body_path.clone(),
            &pool,
            Some(tx.clone()),
            Some(cancel.clone()),
        )
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))
    } else {
        index_partition_with_options_report(
            evidence_id,
            partition_id,
            size_sectors,
            first_byte_addr,
            body_path.clone(),
            format,
            &body_options,
            &pool,
            Some(tx.clone()),
            Some(cancel.clone()),
        )
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))
    };

    drop(tx);
    let _ = monitor.await;
    let mut report = index_result?;
    if !recovery_options.retry
        && matches!(
            report.status,
            exhume_indexer::IndexStatus::Cancelled | exhume_indexer::IndexStatus::Aborted
        )
    {
        if matches.get_flag("json_report") {
            println!("{}", serde_json::to_string(&report)?);
        }
        return Ok(if report.status == exhume_indexer::IndexStatus::Cancelled {
            130
        } else {
            1
        });
    }

    if run_identify_files || run_extract_artefacts || recovery_options.retry {
        let mut fs = reopen_input(
            &body_path,
            format,
            is_directory,
            first_byte_addr,
            size_sectors,
            matches
                .get_one::<String>("fvek")
                .map(String::as_str)
                .or(retry_fvek.as_deref()),
            &body_options,
        )?;

        use exhume_indexer::report::{run_reported_phase, IndexPhase};
        if run_identify_files {
            let (tx, rx) = mpsc::channel::<IndexerEvent>(100);
            let monitor = tokio::spawn(progress_monitor(rx, progress_enabled));
            let result = run_reported_phase(
                &pool,
                &mut report,
                IndexPhase::FileSignature,
                Some(tx.clone()),
                Some(cancel.clone()),
                |sender| async {
                    identify_file_types(&mut fs, evidence_id, partition_id, &pool, Some(sender))
                        .await;
                },
            )
            .await;
            drop(tx);
            let _ = monitor.await;
            result.map_err(|e| anyhow::anyhow!(e.to_string()))?;
        }
        if run_extract_artefacts {
            let registry = build_registry();
            let (tx, rx) = mpsc::channel::<IndexerEvent>(100);
            let monitor = tokio::spawn(progress_monitor(rx, progress_enabled));
            let result = run_reported_phase(
                &pool,
                &mut report,
                IndexPhase::ArtifactIdentification,
                Some(tx.clone()),
                Some(cancel.clone()),
                |sender| async {
                    identify_artefacts(
                        evidence_id,
                        partition_id,
                        &pool,
                        Some(sender),
                        artifacts_yaml_path,
                    )
                    .await;
                },
            )
            .await;
            drop(tx);
            let _ = monitor.await;
            result.map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let (tx, rx) = mpsc::channel::<IndexerEvent>(100);
            let monitor = tokio::spawn(progress_monitor(rx, progress_enabled));
            let result = recovery::run_reported_recovery(
                &pool,
                &mut fs,
                &registry,
                &mut recovery_session,
                &mut report,
                None,
                true,
                Some(tx.clone()),
                cancel.clone(),
            )
            .await;
            drop(tx);
            let _ = monitor.await;
            recovery_report = result?;
            if report.status != exhume_indexer::IndexStatus::Cancelled {
                let timeline_pool = &pool;
                run_reported_phase(
                    &pool,
                    &mut report,
                    IndexPhase::ArtifactExtraction,
                    None,
                    Some(cancel.clone()),
                    |sender| async move {
                        if let Err(error) =
                            populate_filesystem_timeline(evidence_id, partition_id, timeline_pool)
                                .await
                        {
                            let _ = sender
                                .send(IndexerEvent {
                                    evidence_id,
                                    event_type: IndexerEventType::Issue {
                                        phase: IndexPhase::ArtifactExtraction,
                                        code: exhume_indexer::report::IndexIssueCode::Database,
                                        path: None,
                                        record_id: None,
                                        fatal: true,
                                    },
                                    message: format!(
                                        "Failed to populate filesystem timeline: {error}"
                                    ),
                                })
                                .await;
                        }
                    },
                )
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            }
        }

        if recovery_options.retry {
            let current = recovery::load_recovery_jobs(
                &pool,
                RecoveryScope {
                    evidence_id,
                    partition_id,
                },
            )
            .await?;
            anyhow::ensure!(!current.jobs.is_empty() || !matches!(report.status, exhume_indexer::IndexStatus::Cancelled | exhume_indexer::IndexStatus::Aborted),
                "the prior run stopped before recovery discovery; rerun --extract-artefacts to establish its analysis coverage");
            recovery_options.validate_scope(&current)?;
            let selected = if recovery_options.selected.is_empty() {
                current
                    .jobs
                    .iter()
                    .filter(|job| !job.status.is_published())
                    .map(|job| job.target_id.clone())
                    .collect::<Vec<_>>()
            } else {
                recovery_options.selected.clone()
            };
            let registry = build_registry();
            recovery::run_reported_recovery(
                &pool,
                &mut fs,
                &registry,
                &mut recovery_session,
                &mut report,
                Some(&selected),
                false,
                None,
                cancel.clone(),
            )
            .await?;
            recovery_report = recovery::load_recovery_jobs(
                &pool,
                RecoveryScope {
                    evidence_id,
                    partition_id,
                },
            )
            .await?;
        }
        if run_extract_artefacts || recovery_options.retry {
            if !recovery_options.retry {
                recovery_options.validate_scope(&recovery_report)?;
            }
            if !cancel.load(std::sync::atomic::Ordering::Relaxed) {
                let selected = recovery_options.prompt(&recovery_report, &mut recovery_session)?;
                if !selected.is_empty() {
                    let registry = build_registry();
                    recovery::run_reported_recovery(
                        &pool,
                        &mut fs,
                        &registry,
                        &mut recovery_session,
                        &mut report,
                        Some(&selected),
                        false,
                        None,
                        cancel.clone(),
                    )
                    .await?;
                    recovery_report = recovery::load_recovery_jobs(
                        &pool,
                        RecoveryScope {
                            evidence_id,
                            partition_id,
                        },
                    )
                    .await?;
                }
            }
        }
    }
    // Discovery already announced its summary through the progress channel.
    // Analysis passes can change that status, so report their final coverage.
    if matches.get_flag("identify_files")
        || matches.get_flag("extract_artefacts")
        || recovery_options.retry
    {
        if report.status == exhume_indexer::IndexStatus::CompletedWithIssues {
            log::warn!("{}", report.summary());
        } else {
            log::info!("{}", report.summary());
        }
    }
    if matches.get_flag("json_report") {
        let mut json = serde_json::to_value(&report)?;
        json.as_object_mut()
            .context("index report must serialize as an object")?
            .insert("recovery".into(), serde_json::to_value(&recovery_report)?);
        println!("{}", serde_json::to_string(&json)?);
    }
    Ok(if report.status == exhume_indexer::IndexStatus::Cancelled {
        130
    } else if report.status == exhume_indexer::IndexStatus::Complete {
        0
    } else {
        2
    })
}

fn default_database_path(body_path: &str) -> PathBuf {
    let path = Path::new(body_path);
    let file_name = path.file_name().unwrap_or(path.as_os_str());
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
    options: &BodyOpenOptions,
) -> Result<impl exhume_filesystem::Filesystem<FileType: Send> + Send> {
    if is_directory {
        return detect_filesystem_from_path(body_path).map_err(|e| anyhow::anyhow!(e.to_string()));
    }

    let body = Body::open(body_path.to_owned(), format, options)?;
    let sector_size = body.get_sector_size() as u64;
    let partition_size_bytes = size_sectors * sector_size;
    let key_material = parse_key_material(fvek_hex)?;

    detect_filesystem(&body, first_byte_addr, partition_size_bytes, key_material)
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
            IndexerEventType::ParserProgress { current, total, .. } => {
                if bar.length() != Some(total) {
                    bar.set_style(progress_style());
                    bar.set_length(total);
                }
                bar.set_position(current.saturating_sub(1).min(total));
                bar.set_message(event.message);
            }
            IndexerEventType::Success => {
                bar.finish_with_message(event.message);
            }
            IndexerEventType::WalkIssue(_) => {}
            IndexerEventType::Warning => log::warn!("{}", event.message),
            IndexerEventType::Issue { fatal, .. } => {
                if fatal {
                    log::error!("{}", event.message);
                } else {
                    log::warn!("{}", event.message);
                }
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
            IndexerEventType::WalkIssue(_) => {}
            IndexerEventType::Info | IndexerEventType::Success => log::info!("{}", event.message),
            IndexerEventType::Progress { current, total } => {
                log::info!("{current}/{total}: {}", event.message)
            }
            IndexerEventType::ParserProgress {
                parser,
                phase,
                current,
                total,
                ..
            } => log::info!(
                "{current}/{total} {parser} {}: {}",
                phase.as_str(),
                event.message
            ),
            IndexerEventType::Warning => log::warn!("{}", event.message),
            IndexerEventType::Issue { fatal, .. } => {
                if fatal {
                    log::error!("{}", event.message);
                } else {
                    log::warn!("{}", event.message);
                }
            }
            IndexerEventType::Error => log::error!("{}", event.message),
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

/// Register this executable's mutually exclusive container-password sources.
fn password_args(command: clap::Command) -> clap::Command {
    command
        .arg(
            clap::Arg::new("password_file")
                .long("password-file")
                .global(true)
                .value_name("PATH")
                .conflicts_with("password_stdin")
                .help("Read the image container password from a file; remove one trailing line ending."),
        )
        .arg(
            clap::Arg::new("password_stdin")
                .long("password-stdin")
                .global(true)
                .action(clap::ArgAction::SetTrue)
                .help("Read the image container password from stdin; remove one trailing line ending."),
        )
}
