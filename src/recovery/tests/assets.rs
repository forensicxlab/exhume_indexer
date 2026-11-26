use super::*;
use crate::assets::{self, AssetErrorCode, AssetLimits};
use exhume_artefacts::assets::Rendition;
use std::{io::Read, sync::atomic::AtomicBool};

fn media() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/signal-attachment.json")).unwrap()
}
async fn fixture(root: &Path, corrupt: bool) -> Result<()> {
    let profile = root.join("home/alice/.config/Signal");
    let path = profile.join("sql/db.sqlite");
    database(&path, false, false).await?;
    let v = media();
    let json = serde_json::json!({"attachments":[{"contentType":"image/png","path":"ab/photo","fileName":"image.png","size":v["size"],"version":2,"localKey":v["key"],"plaintextHash":v["plaintext_sha256"]}]});
    let mut db =
        SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path)).await?;
    sqlx::query("UPDATE messages SET json=? WHERE id='m2'")
        .bind(json.to_string())
        .execute(&mut db)
        .await?;
    db.close().await?;
    let mut bytes = hex::decode(v["ciphertext_hex"].as_str().unwrap())?;
    if corrupt {
        bytes[17] ^= 1;
    }
    std::fs::create_dir_all(profile.join("attachments.noindex/ab"))?;
    std::fs::write(profile.join("attachments.noindex/ab/photo"), bytes)?;
    Ok(())
}
async fn reference(pool: &SqlitePool) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT id FROM artifact_attachment_refs WHERE parser='desktop_signal' LIMIT 1",
    )
    .fetch_one(pool)
    .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_assets_resume_from_cache_and_preserve_inventory_and_messages() -> Result<()> {
    let root = tempfile::tempdir()?;
    fixture(root.path(), false).await?;
    let output = tempfile::tempdir()?;
    let (pool, scope, mut fs, inventory) = index(root.path()).await?;
    let parsed = process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
    assert_eq!(parsed.jobs[0].status, RecoveryStatus::Complete);
    let id = reference(&pool).await?;
    let source = root
        .path()
        .join("home/alice/.config/Signal/attachments.noindex/ab/photo");
    let original = std::fs::read(&source)?;
    let prepared = assets::prepare_asset(
        &pool,
        &exhume_artefacts::parsers::build_registry(),
        scope,
        id,
        Rendition::Original,
    )
    .await?;
    let generation = prepared.generation.clone();
    let asset = assets::recover_asset(
        &pool,
        &exhume_artefacts::parsers::build_registry(),
        &mut fs,
        prepared,
        output.path(),
        &AssetLimits::default(),
        None,
    )
    .await?;
    assert!(!asset.cache_hit);
    assert_eq!(
        asset.record.output.proof.plaintext_sha256,
        media()["plaintext_sha256"]
    );
    assert_eq!(
        asset.record.source.sha256.as_deref(),
        media()["ciphertext_sha256"].as_str()
    );
    let count = std::fs::read_dir(output.path())?.count();
    assert_eq!(count, 1);
    drop(asset);
    let prepared = assets::prepare_asset(
        &pool,
        &exhume_artefacts::parsers::build_registry(),
        scope,
        id,
        Rendition::Original,
    )
    .await?;
    let mut cached = assets::open_cached_asset(&pool, &prepared, output.path(), None)
        .await?
        .unwrap();
    let mut recovered = Vec::new();
    cached.file.read_to_end(&mut recovered)?;
    assert!(cached.cache_hit);
    assert_eq!(
        recovered,
        hex::decode(media()["plaintext_hex"].as_str().unwrap())?
    );
    assert_eq!(generation, assets::asset_generation(&pool).await?);
    assert_eq!(std::fs::read(&source)?, original);
    assert_eq!(
        load_recovery_jobs(&pool, scope).await?.jobs[0].object_count,
        6
    );
    assert_eq!(
        crate::latest_inventory_report(&pool, scope.evidence_id, scope.partition_id)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
            .unwrap()
            .run_id,
        inventory.run_id
    );
    assert_eq!(std::fs::read_dir(output.path())?.count(), count);
    Ok(())
}

#[tokio::test]
async fn corrupt_media_and_cancelled_requests_do_not_affect_published_messages() -> Result<()> {
    for corrupt in [false, true] {
        let root = tempfile::tempdir()?;
        fixture(root.path(), corrupt).await?;
        let output = tempfile::tempdir()?;
        let (pool, scope, mut fs, _) = index(root.path()).await?;
        process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
        let prepared = assets::prepare_asset(
            &pool,
            &exhume_artefacts::parsers::build_registry(),
            scope,
            reference(&pool).await?,
            Rendition::Original,
        )
        .await?;
        let cancel = AtomicBool::new(!corrupt);
        let result = assets::recover_asset(
            &pool,
            &exhume_artefacts::parsers::build_registry(),
            &mut fs,
            prepared,
            output.path(),
            &AssetLimits::default(),
            Some(&cancel),
        )
        .await;
        let failure = match result {
            Err(error) => error,
            Ok(_) => anyhow::bail!("invalid/cancelled media unexpectedly succeeded"),
        };
        assert_eq!(
            failure.code,
            if corrupt {
                AssetErrorCode::AuthenticationFailed
            } else {
                AssetErrorCode::Cancelled
            }
        );
        assert_eq!(std::fs::read_dir(output.path())?.count(), 0);
        assert_eq!(
            load_recovery_jobs(&pool, scope).await?.jobs[0].status,
            RecoveryStatus::Complete
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifact_objects WHERE parser='desktop_signal'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(count, 6);
    }
    Ok(())
}

#[tokio::test]
async fn changed_cache_is_recovered_again_and_scope_inventory_are_checked() -> Result<()> {
    let root = tempfile::tempdir()?;
    fixture(root.path(), false).await?;
    let output = tempfile::tempdir()?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
    let id = reference(&pool).await?;
    let prepared = assets::prepare_asset(
        &pool,
        &exhume_artefacts::parsers::build_registry(),
        scope,
        id,
        Rendition::Original,
    )
    .await?;
    let asset = assets::recover_asset(
        &pool,
        &exhume_artefacts::parsers::build_registry(),
        &mut fs,
        prepared,
        output.path(),
        &AssetLimits::default(),
        None,
    )
    .await?;
    std::fs::write(
        output.path().join(&asset.record.output.relative_path),
        vec![0; asset.record.output.proof.plaintext_size as usize],
    )?;
    let prepared = assets::prepare_asset(
        &pool,
        &exhume_artefacts::parsers::build_registry(),
        scope,
        id,
        Rendition::Original,
    )
    .await?;
    assert!(
        assets::open_cached_asset(&pool, &prepared, output.path(), None)
            .await?
            .is_none()
    );
    let replaced = assets::recover_asset(
        &pool,
        &exhume_artefacts::parsers::build_registry(),
        &mut fs,
        prepared,
        output.path(),
        &AssetLimits::default(),
        None,
    )
    .await?;
    assert!(!replaced.cache_hit);
    assert_eq!(
        replaced.record.output.proof.plaintext_sha256,
        media()["plaintext_sha256"]
    );
    assert_eq!(
        assets::prepare_asset(
            &pool,
            &exhume_artefacts::parsers::build_registry(),
            RecoveryScope {
                evidence_id: 2,
                ..scope
            },
            id,
            Rendition::Original
        )
        .await
        .unwrap_err()
        .code,
        AssetErrorCode::StaleReference
    );
    assert_eq!(
        assets::prepare_asset(
            &pool,
            &exhume_artefacts::parsers::build_registry(),
            scope,
            id,
            Rendition::Thumbnail
        )
        .await
        .unwrap_err()
        .code,
        AssetErrorCode::InvalidMetadata
    );
    sqlx::query("DELETE FROM index_inventory WHERE evidence_id=? AND partition_id=?")
        .bind(scope.evidence_id)
        .bind(scope.partition_id)
        .execute(&pool)
        .await?;
    assert_eq!(
        assets::prepare_asset(
            &pool,
            &exhume_artefacts::parsers::build_registry(),
            scope,
            id,
            Rendition::Original
        )
        .await
        .unwrap_err()
        .code,
        AssetErrorCode::StaleReference
    );
    Ok(())
}

#[tokio::test]
async fn fresh_catalogues_have_distinct_generations() -> Result<()> {
    let first = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let second = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    assert_ne!(
        assets::asset_generation(&first).await?,
        assets::asset_generation(&second).await?
    );
    Ok(())
}

#[tokio::test]
async fn cache_quotas_fail_before_publishing_and_do_not_remove_messages() -> Result<()> {
    let root = tempfile::tempdir()?;
    fixture(root.path(), false).await?;
    let output = tempfile::tempdir()?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    process(&pool, scope, &mut fs, &mut RecoverySession::default()).await?;
    let id = reference(&pool).await?;
    let prepared = assets::prepare_asset(
        &pool,
        &exhume_artefacts::parsers::build_registry(),
        scope,
        id,
        Rendition::Original,
    )
    .await?;
    let limits = AssetLimits {
        cache_bytes: 1,
        ..AssetLimits::default()
    };
    let result = assets::recover_asset(
        &pool,
        &exhume_artefacts::parsers::build_registry(),
        &mut fs,
        prepared,
        output.path(),
        &limits,
        None,
    )
    .await;
    assert!(matches!(
        result,
        Err(assets::AssetError {
            code: AssetErrorCode::LimitExceeded
        })
    ));
    assert_eq!(std::fs::read_dir(output.path())?.count(), 0);
    std::fs::write(output.path().join("existing"), b"cache")?;
    let prepared = assets::prepare_asset(
        &pool,
        &exhume_artefacts::parsers::build_registry(),
        scope,
        id,
        Rendition::Original,
    )
    .await?;
    let limits = AssetLimits {
        cache_files: 1,
        ..AssetLimits::default()
    };
    let result = assets::recover_asset(
        &pool,
        &exhume_artefacts::parsers::build_registry(),
        &mut fs,
        prepared,
        output.path(),
        &limits,
        None,
    )
    .await;
    assert!(matches!(
        result,
        Err(assets::AssetError {
            code: AssetErrorCode::LimitExceeded
        })
    ));
    assert_eq!(std::fs::read(output.path().join("existing"))?, b"cache");
    assert_eq!(
        load_recovery_jobs(&pool, scope).await?.jobs[0].object_count,
        6
    );
    Ok(())
}

#[tokio::test]
async fn plaintext_whatsapp_assets_use_the_shared_catalogue_without_a_recovery_job() -> Result<()> {
    let root = tempfile::tempdir()?;
    let container = root
        .path()
        .join("Users/alice/Library/Group Containers/group.net.whatsapp.WhatsApp.shared");
    std::fs::create_dir_all(container.join("Message/Media"))?;
    std::fs::write(
        container.join("ChatStorage.sqlite"),
        b"invented primary source",
    )?;
    let payload = b"invented plaintext media";
    std::fs::write(container.join("Message/Media/example.txt"), payload)?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    // Insert a published plaintext-parser reference. This exercises the catalogue
    // independently of any credential-preparation job or Signal record shape.
    let (file_id, primary): (i64, String) =
        sqlx::query_as("SELECT id,absolute_path FROM system_files WHERE name='ChatStorage.sqlite'")
            .fetch_one(&pool)
            .await?;
    sqlx::query("DELETE FROM artifacts WHERE file_id=?")
        .bind(file_id)
        .execute(&pool)
        .await?;
    let artifact=sqlx::query("INSERT INTO artifacts(evidence_id,partition_id,file_id,name,description,parser,tag,category) VALUES(1,1,?,'WhatsApp','','mobile_ios_whatsapp','test','test')").bind(file_id).execute(&pool).await?.last_insert_rowid();
    let json = serde_json::json!({"source":{"path":primary,"table":"ZWAMEDIAITEM","rowid":1},"app":{"label":"WhatsApp"},"attachment":{"local_path":"Message/Media/example.txt","mime":"text/plain","kind":"document"},"media":{"file_size":payload.len()}});
    let object=sqlx::query("INSERT INTO artifact_objects(evidence_id,partition_id,artifact_id,file_id,parser,kind,json) VALUES(1,1,?,?,'mobile_ios_whatsapp','mobile.communication.attachment',?)").bind(artifact).bind(file_id).bind(json.to_string()).execute(&pool).await?.last_insert_rowid();
    let mut tx = pool.begin().await?;
    crate::artifacts::insert_attachment_ref(
        &mut tx,
        1,
        1,
        object,
        "mobile_ios_whatsapp",
        &json,
        None,
    )
    .await?;
    tx.commit().await?;
    let reference = sqlx::query_scalar("SELECT id FROM artifact_attachment_refs")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count(&pool, "recovery_jobs").await, 0);
    let registry = build_registry();
    let output = tempfile::tempdir()?;
    let prepared =
        assets::prepare_asset(&pool, &registry, scope, reference, Rendition::Original).await?;
    let asset = assets::recover_asset(
        &pool,
        &registry,
        &mut fs,
        prepared,
        output.path(),
        &AssetLimits::default(),
        None,
    )
    .await?;
    assert_eq!(asset.record.output.proof.authentication, "plaintext");
    assert!(!asset.record.output.proof.metadata_hash_checked);
    let mut file = asset.file;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    assert_eq!(bytes, payload);
    assert_eq!(
        std::fs::read(container.join("Message/Media/example.txt"))?,
        payload
    );
    Ok(())
}

#[derive(Debug)]
struct NestedMedia(exhume_artefacts::assets::PlaintextSpec);
impl exhume_artefacts::assets::AssetRecipe for NestedMedia {
    fn local_path(&self) -> &str {
        self.0.local_path()
    }
    fn mime(&self) -> Option<&str> {
        self.0.mime()
    }
    fn plaintext_size(&self) -> Option<u64> {
        self.0.plaintext_size()
    }
    fn fingerprint(&self) -> String {
        self.0.fingerprint()
    }
    fn base_directory(&self) -> Option<&str> {
        Some("media/blobs")
    }
    fn recover(
        &self,
        input: &mut dyn exhume_artefacts::core::ReadSeek,
        output: &mut dyn std::io::Write,
        maximum: u64,
        cancel: Option<&AtomicBool>,
    ) -> exhume_artefacts::assets::Result<exhume_artefacts::assets::AssetProof> {
        self.0.recover(input, output, maximum, cancel)
    }
}
struct DifferentMediaParser;
impl exhume_artefacts::Parser for DifferentMediaParser {
    fn name(&self) -> &'static str {
        "example_media"
    }
    fn run_into(
        &self,
        _input: ParserInput,
        _sink: &mut dyn FnMut(exhume_artefacts::ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        anyhow::bail!("test uses an already published reference")
    }
    fn asset_root(&self, primary: &Path) -> Option<std::path::PathBuf> {
        primary.parent()?.parent().map(Path::to_path_buf)
    }
    fn attachment_recipe(
        &self,
        record: &serde_json::Value,
        rendition: Rendition,
    ) -> exhume_artefacts::assets::Result<Option<Box<dyn exhume_artefacts::assets::AssetRecipe>>>
    {
        Ok(Some(Box::new(NestedMedia(
            exhume_artefacts::assets::PlaintextSpec::from_record(record, rendition)?,
        ))))
    }
}
#[tokio::test]
async fn another_app_declares_its_media_root_without_an_indexer_dispatch_branch() -> Result<()> {
    let root = tempfile::tempdir()?;
    let app = root.path().join("home/alice/ExampleApp");
    std::fs::create_dir_all(app.join("state"))?;
    std::fs::create_dir_all(app.join("media/blobs/ab"))?;
    std::fs::write(app.join("state/data.bin"), b"invented source")?;
    std::fs::write(app.join("media/blobs/ab/file"), b"correct media")?;
    let other = root.path().join("home/bob/ExampleApp/media/blobs/ab");
    std::fs::create_dir_all(&other)?;
    std::fs::write(other.join("file"), b"wrong account")?;
    let (pool, scope, mut fs, _) = index(root.path()).await?;
    let (file_id, primary): (i64, String) =
        sqlx::query_as("SELECT id,absolute_path FROM system_files WHERE name='data.bin'")
            .fetch_one(&pool)
            .await?;
    let artifact=sqlx::query("INSERT INTO artifacts(evidence_id,partition_id,file_id,name,description,parser,tag,category) VALUES(1,1,?,'Example','','example_media','test','test')").bind(file_id).execute(&pool).await?.last_insert_rowid();
    let mut json = serde_json::json!({"source":{"path":primary},"attachment":{"local_path":"ab/file","mime":"text/plain","kind":"document"}});
    let object=sqlx::query("INSERT INTO artifact_objects(evidence_id,partition_id,artifact_id,file_id,parser,kind,json) VALUES(1,1,?,?,'example_media','mobile.communication.attachment',?)").bind(artifact).bind(file_id).bind(json.to_string()).execute(&pool).await?.last_insert_rowid();
    let mut tx = pool.begin().await?;
    crate::artifacts::insert_attachment_ref(&mut tx, 1, 1, object, "example_media", &json, None)
        .await?;
    tx.commit().await?;
    let reference = sqlx::query_scalar("SELECT id FROM artifact_attachment_refs")
        .fetch_one(&pool)
        .await?;
    let mut registry = build_registry();
    registry.insert("example_media", Arc::new(DifferentMediaParser));
    let output = tempfile::tempdir()?;
    let prepared =
        assets::prepare_asset(&pool, &registry, scope, reference, Rendition::Original).await?;
    assert!(prepared
        .source
        .path
        .contains("/alice/ExampleApp/media/blobs/ab/file"));
    let mut asset = assets::recover_asset(
        &pool,
        &registry,
        &mut fs,
        prepared,
        output.path(),
        &AssetLimits::default(),
        None,
    )
    .await?;
    let mut bytes = Vec::new();
    asset.file.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"correct media");
    json["attachment"]["local_path"] = "/home/bob/ExampleApp/media/blobs/ab/file".into();
    sqlx::query("UPDATE artifact_attachment_refs SET json=? WHERE id=?")
        .bind(json.to_string())
        .bind(reference)
        .execute(&pool)
        .await?;
    assert_eq!(
        assets::prepare_asset(&pool, &registry, scope, reference, Rendition::Original)
            .await
            .unwrap_err()
            .code,
        AssetErrorCode::InvalidMetadata
    );
    Ok(())
}
