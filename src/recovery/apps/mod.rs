//! Register preparation capabilities by the same identifiers as the parser registry.
mod signal;
use super::*;
#[derive(Default)]
pub struct BuiltinPreparation;
enum Application {
    Signal,
}
fn application(parser: &str) -> Option<Application> {
    match parser {
        "desktop_signal" => Some(Application::Signal),
        _ => None,
    }
}
pub fn manages_parser(parser: &str) -> bool {
    application(parser).is_some()
}
impl<F> RecoveryPreparation<F> for BuiltinPreparation
where
    F: Filesystem + Send,
    F::FileType: FileCommon + Send,
{
    fn supports_parser(&self, parser: &str) -> bool {
        manages_parser(parser)
    }
    fn describe(&self, parser: &str, source: &RecoverySource) -> Option<TargetDescription> {
        match application(parser)? {
            Application::Signal => {
                let (root_path, platform) = signal::profile(&source.path);
                Some(TargetDescription {
                    application: "Signal Desktop".into(),
                    root_path,
                    platform,
                })
            }
        }
    }
    async fn prepare(&self, context: PreparationContext<'_, F>) -> Result<PreparedParser> {
        match application(&context.job.parser) {
            Some(Application::Signal) => signal::prepare(context).await,
            _ => Err(blocked(
                RecoveryStatus::Unsupported,
                "preparation_not_registered",
            )),
        }
    }
}
