use std::collections;
use std::env;
use std::net;

use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct General {
    pub dns_port: u16,
    pub web_port: u16,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Address {
    #[serde(skip)]
    pub ipv4: Option<net::Ipv4Addr>,
    #[serde(skip)]
    pub ipv6: Option<net::Ipv6Addr>,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for General {
    fn default() -> Self {
        General {
            dns_port: 5353,
            web_port: 8080,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Settings {
    pub general: General,
    pub addresses: collections::HashMap<String, Address>,
}

impl Settings {
    pub fn load() -> Result<Self, ConfigError> {
        let mut c = Config::new();

        //let package_name = env!("CARGO_PKG_NAME");
        //s.merge(File::with_name(&format!("/etc/{}/config", package_name)).required(false))?;

        let env = env::var("RUN_MODE").unwrap_or("development".into());
        c.merge(File::with_name(&format!("config/{}", env)).required(false))?;

        c.try_into()
    }
}
