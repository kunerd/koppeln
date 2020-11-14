use std::collections;
use std::env;
use std::net;

use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AddressConfig {
    #[serde(skip)]
    pub ipv4: Option<net::Ipv4Addr>,
    #[serde(skip)]
    pub ipv6: Option<net::Ipv6Addr>,
    pub token: String, //pub username: Option<String>,
                       //pub password: Option<String>
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            dns_address: net::IpAddr::V4(net::Ipv4Addr::new(127, 0, 0, 1)),
            dns_port: 53,
            web_address: net::IpAddr::V4(net::Ipv4Addr::new(127, 0, 0, 1)),
            web_port: 80,
            addresses: collections::HashMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub dns_address: net::IpAddr,
    pub dns_port: u16,
    pub web_address: net::IpAddr,
    pub web_port: u16,
    pub addresses: collections::HashMap<String, AddressConfig>,
}

impl Settings {
    pub fn load() -> Result<Self, ConfigError> {
        let mut c = Config::new();

        let env = env::var("RUN_MODE").unwrap_or("development".into());
        c.merge(File::with_name(&format!("/etc/dyndns/config/{}", env)).required(false))?;
        c.merge(File::with_name(&format!("config/{}", env)).required(false))?;

        c.merge(Environment::with_prefix("dyndns"))?;

        c.try_into()
    }
}
