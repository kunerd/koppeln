pub mod dns;
mod parser;
pub mod settings;
mod storage;
pub mod web;

use std::sync::{Arc, Mutex};

pub use storage::Storage;

pub type SharedStorage = Arc<Mutex<Storage>>;
