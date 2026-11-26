use super::*;
use std::io::{BufWriter, Seek, SeekFrom, Write};
#[derive(Serialize, Deserialize)]
pub(super) struct StagedTimeline {
    pub(super) ts: i64,
    pub(super) event_type: String,
    pub(super) description: Option<String>,
    pub(super) actor: Option<String>,
}
#[derive(Serialize, Deserialize)]
pub(super) struct StagedRecord {
    pub(super) kind: String,
    pub(super) text: String,
    pub(super) json: serde_json::Value,
    pub(super) timeline: Vec<StagedTimeline>,
}
pub(super) struct RecordSpool {
    writer: BufWriter<std::fs::File>,
    maximum: u64,
    written: u64,
    pub(super) count: u64,
    records: u64,
    pub(super) limit_hit: bool,
    pub(super) io_failed: bool,
}
impl RecordSpool {
    pub(super) fn new(maximum: u64, records: u64) -> Result<Self> {
        Ok(Self {
            writer: BufWriter::new(tempfile::tempfile()?),
            maximum,
            written: 0,
            count: 0,
            records,
            limit_hit: false,
            io_failed: false,
        })
    }
    pub(super) fn append<T: Serialize>(&mut self, item: &T) -> Result<()> {
        if self.count >= self.records {
            self.limit_hit = true;
            return Err(blocked(RecoveryStatus::LimitExceeded, "record_count_limit"));
        }
        let remaining = self
            .maximum
            .saturating_sub(self.written)
            .saturating_sub(1)
            .min(8 * 1024 * 1024);
        let mut encoded = LimitedJson {
            bytes: Vec::new(),
            remaining,
            hit: false,
        };
        if let Err(error) = serde_json::to_writer(&mut encoded, item) {
            if encoded.hit {
                self.limit_hit = true;
                return Err(blocked(
                    RecoveryStatus::LimitExceeded,
                    "record_output_limit",
                ));
            }
            return Err(error.into());
        }
        let bytes = encoded.bytes;
        let length = u64::try_from(bytes.len())?
            .checked_add(1)
            .context("Recovery spool size overflow")?;
        if length > 8 * 1024 * 1024
            || self
                .written
                .checked_add(length)
                .is_none_or(|n| n > self.maximum)
        {
            self.limit_hit = true;
            return Err(blocked(
                RecoveryStatus::LimitExceeded,
                "record_output_limit",
            ));
        }
        if let Err(error) = self
            .writer
            .write_all(&bytes)
            .and_then(|_| self.writer.write_all(b"\n"))
        {
            self.io_failed = true;
            return Err(error.into());
        }
        self.written += length;
        self.count += 1;
        Ok(())
    }
    pub(super) fn finish(mut self) -> Result<std::fs::File> {
        self.writer.flush()?;
        let mut file = self.writer.into_inner().map_err(std::io::Error::other)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
}

struct LimitedJson {
    bytes: Vec<u8>,
    remaining: u64,
    hit: bool,
}
impl Write for LimitedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let length = u64::try_from(bytes.len()).map_err(std::io::Error::other)?;
        if length > self.remaining {
            self.hit = true;
            return Err(std::io::Error::other(
                "Recovery JSON record exceeds its byte budget",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        self.remaining -= length;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
