extern crate nom;

use std::net::Ipv4Addr;

use std::collections::HashMap;
use std::path::{PathBuf, Path};
use std::time::Duration;

use test_helper::drill::{parse_drill_output, DrillOutput};
use test_helper::linux_containers::LxcContainer;

struct KoppelnContainer {
    base_container: LxcContainer,
}

impl KoppelnContainer {
    fn new() -> Self {
        Self {
            base_container: LxcContainer::new("koppeln".into()),
        }
    }

    fn load_config_file(&self, path: impl AsRef<Path>) {
        // push default config file
        let mut config_src_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        config_src_path.push(path);

        let output = self.base_container
            .file_push(&config_src_path, &"etc/koppeln/config.toml")
            .unwrap();
    }

    fn restart_service(&self) {
        self.base_container
            .exec(&|cmd| cmd.arg("systemctl").arg("restart").arg("koppeln.service"))
            .expect("Could not restart koppeln service!");
    }

    fn wait_until_service_is_ready(&self) {
        loop {
            let output = self.base_container.exec(&|cmd| {
                cmd.arg("systemctl")
                    .arg("is-active")
                    .arg("--quiet")
                    .arg("koppeln.service")
            });

            if output.is_ok() && output.unwrap().status.success() {
                break;
            }

            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

struct DrillContainer {
    base_container: LxcContainer
}

impl DrillContainer {
    fn new() -> Self {
        DrillContainer {
            base_container: LxcContainer::new("drill".into())
        }
    }

    fn resolve_domain_name(&self, name: &str, server: Option<&str>) -> DrillOutput {
        let output = self.base_container
            .exec(&|cmd| {
                let cmd = cmd.arg("drill").arg(name);
                match server {
                    Some(s) => cmd.arg(s),
                    None => cmd
                }
            })
            .unwrap();

        let (_, drill) = parse_drill_output(std::str::from_utf8(&output.stdout).unwrap())
            .ok()
            .unwrap();

        drill
    }
}


#[test]
fn test_query_unknown_domain() {
    let drill_container = DrillContainer::new();
    let koppeln_container = KoppelnContainer::new();

    koppeln_container.restart_service();
    koppeln_container.wait_until_service_is_ready();

    let drill_output = drill_container.resolve_domain_name("koppeln.lxd", None);
    let dns_server = format!("@{}", drill_output.answer.unwrap().ip);

    let drill_output = drill_container.resolve_domain_name("unknown.dyn.example.com", Some(&dns_server));

    assert_eq!(drill_output.answer, None)
}

#[test]
fn test_query_domain_without_ip() {
    let drill_container = DrillContainer::new();
    let koppeln_container = KoppelnContainer::new();

    koppeln_container.load_config_file("fixtures/base_config.toml");
    koppeln_container.restart_service();
    koppeln_container.wait_until_service_is_ready();

    let drill_output = drill_container.resolve_domain_name("koppeln.lxd", None);
    let dns_server = format!("@{}", drill_output.answer.unwrap().ip);

    let drill_output = drill_container
        .resolve_domain_name("test.dyn.example.com", Some(&dns_server));

    assert_eq!(drill_output.answer, None)
}

#[test]
fn test_set_ip_for_domain_name() {
    let drill_container = DrillContainer::new();
    let koppeln_container = KoppelnContainer::new();

    koppeln_container.load_config_file("fixtures/base_config.toml");
    koppeln_container.restart_service();
    koppeln_container.wait_until_service_is_ready();

    let drill_output = drill_container.resolve_domain_name("koppeln.lxd", None);
    let dns_server = format!("@{}", drill_output.answer.unwrap().ip);


    // set ip
    let mut map = HashMap::new();
    map.insert("hostname", "test.dyn.example.com");
    map.insert("ip", "1.2.3.4");

    let client = reqwest::blocking::Client::new();
    client
        .put(format!("http://{}/hostname", dns_server))
        .header("Authorization", "super_secure")
        .json(&map)
        .send()
        .expect("Could not set new IP address");

    let drill_output = drill_container
        .resolve_domain_name("test.dyn.example.com", Some(&dns_server));

    let answer = drill_output.answer.unwrap();
    assert_eq!(answer.domain_name, ".".to_string());
    assert_eq!(answer.ip, Ipv4Addr::new(1, 2, 3, 4));
}
