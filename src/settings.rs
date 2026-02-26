use std::collections::HashMap;
use std::env;
use std::net;

use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};

use crate::dns;
use crate::dns::DomainName;
use crate::storage::SubDomainEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub user: Option<String>,
    pub group: Option<String>,

    pub dns: Dns,
    pub http: Http,

    pub addresses: HashMap<DomainName, SubDomainEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dns {
    pub address: net::IpAddr,
    pub port: u16,

    pub soa: dns::StartOfAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http {
    pub address: net::IpAddr,
    pub port: u16,
}

impl Settings {
    pub fn load() -> Result<Self, ConfigError> {
        let env = env::var("RUN_MODE").unwrap_or_else(|_| "development".to_string());

        let config = Config::builder()
            .add_source(File::with_name("/etc/koppeln/config.toml").required(false))
            .add_source(File::with_name(&format!("config/{}", env)).required(false))
            .add_source(Environment::with_prefix("koppeln"))
            .build()?;

        config.try_deserialize()
    }
}
