//! Application preparation is an extension of the existing parser registry.
//! It resolves inputs/options; record interpretation always uses `Parser`.
use super::*;
use std::future::Future;

pub struct TargetDescription {
    pub application: String,
    pub root_path: String,
    pub platform: RecoveryPlatform,
}
pub struct PreparationContext<'a, F: Filesystem> {
    pub pool: &'a SqlitePool,
    pub filesystem: &'a mut F,
    pub session: &'a RecoverySession,
    pub job: &'a mut RecoveryJob,
    pub cancel: Option<&'a AtomicBool>,
}
/// Options may contain operation-local secrets and are deliberately not serializable.
pub struct PreparedParser {
    pub options: ParserOptions,
    /// Recorded only after the parser succeeds.
    pub validation: String,
}
pub trait RecoveryPreparation<F>: Send + Sync
where
    F: Filesystem + Send,
    F::FileType: FileCommon + Send,
{
    /// `None` leaves the parser on the ordinary extraction path.
    fn describe(&self, parser: &str, primary: &RecoverySource) -> Option<TargetDescription>;
    fn prepare<'a>(
        &'a self,
        context: PreparationContext<'a, F>,
    ) -> impl Future<Output = Result<PreparedParser>> + Send + 'a;
}
