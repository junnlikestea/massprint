extern crate lazy_static;

mod fingerprint;
mod input;
mod inspector;

pub use crate::fingerprint::FingerPrint;
pub use crate::fingerprint::FingerPrintSet;
pub use crate::input::Input;
pub use crate::inspector::Inspector;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
