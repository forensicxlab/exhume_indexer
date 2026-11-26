//! Reusable acquired credential-store providers; never application parsers.
pub(crate) mod dpapi;
pub(crate) mod keychain;
pub(crate) mod linux;
use super::evidence::*;
use super::*;
