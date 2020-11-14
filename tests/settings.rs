extern crate koppeln;

use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use koppeln::settings;

use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

#[test]
#[ignore]
pub fn default_settings() {
    env::set_var("RUN_MODE", "production");
    let s = settings::Settings::load().unwrap();

    assert_eq!(s.web_port, 80);
    assert_eq!(s.dns_port, 53);
}

#[test]
#[ignore]
fn load_production_settings_from_env_file() {
    env::set_var("RUN_MODE", "production");
    let s = settings::Settings::load().unwrap();

    assert_eq!(s.web_port, 80);
    assert_eq!(s.dns_port, 53);
}

#[test]
#[ignore]
fn load_development_settings_by_default() {
    env::remove_var("RUN_MODE");
    let s = settings::Settings::load().unwrap();

    assert_eq!(s.web_port, 8088);
    assert_eq!(s.dns_port, 5354);
}

#[test]
#[ignore]
fn load_addresses() {
    env::remove_var("RUN_MODE");
    let s = settings::Settings::load().unwrap();

    assert_eq!(
        *s.addresses.get("vpn.dyn.example.com").unwrap(),
        settings::AddressConfig {
            ipv4: None,
            ipv6: None,
            token: "super_secure".to_string()
        }
    );
    assert_eq!(
        *s.addresses.get("test.dyn.example.com").unwrap(),
        settings::AddressConfig {
            ipv4: None,
            ipv6: None,
            token: "super_secure".to_string()
        }
    );
}
