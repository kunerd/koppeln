extern crate dns;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use dns::settings;

pub fn write_config(config: &str) -> PathBuf {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), r".tmp", r"config.toml"]
        .iter()
        .collect();

    write_config_at(path.as_path(), config);

    path
}

pub fn write_config_at(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().unwrap());
    fs::write(path, contents).unwrap();
}

#[ignore]
#[test]
pub fn default_settings() {
    env::set_var("RUN_MODE", "nothing");
    let s = settings::Settings::load().unwrap();

    assert_eq!(s.general.web_port, 8080);
    assert_eq!(s.general.dns_port, 5353);
}

#[ignore]
#[test]
fn load_production_settings_from_env_file() {
    env::set_var("RUN_MODE", "production");
    let s = settings::Settings::load().unwrap();

    assert_eq!(s.general.web_port, 80);
    assert_eq!(s.general.dns_port, 53);
}

#[test]
fn load_development_settings_by_default() {
    env::remove_var("RUN_MODE");
    let s = settings::Settings::load().unwrap();

    assert_eq!(s.general.web_port, 8088);
    assert_eq!(s.general.dns_port, 5354);
}

#[test]
fn load_addresses() {
    env::remove_var("RUN_MODE");
    let s = settings::Settings::load().unwrap();

    assert_eq!(
        *s.addresses.get("vpn.dyn.example.com").unwrap(),
        settings::Address {
            ipv4: None,
            ipv6: None,
            username: Some("kunerd".to_string()),
            password: Some("super_secure".to_string())
        }
    );
    assert_eq!(
        *s.addresses.get("test.dyn.example.com").unwrap(),
        settings::Address {
            ipv4: None,
            ipv6: None,
            username: Some("kunerd".to_string()),
            password: None
        }
    );
}
