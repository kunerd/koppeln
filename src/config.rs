use std::fs::File;
use std::io::prelude::Read;

use toml;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    udp_port: u16,
    http_port: u16
}

impl Config {
    pub fn from_file(filepath: &str) -> Self {
        let mut file = File::open(filepath).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        toml::from_str(&content).unwrap()
    }
}
