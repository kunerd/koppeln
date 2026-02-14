pub mod dns;
mod parser;
pub mod settings;
pub mod web;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

pub type AddressStorage = Arc<Mutex<HashMap<String, settings::AddressConfig>>>;
