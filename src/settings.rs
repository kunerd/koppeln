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
    pub dns_address: net::IpAddr,
    pub dns_port: u16,

    pub web_address: net::IpAddr,
    pub web_port: u16,

    pub soa: dns::StartOfAuthority,

    pub addresses: HashMap<DomainName, SubDomainEntry>,
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
