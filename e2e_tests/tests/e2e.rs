extern crate nom;

use std::net::Ipv4Addr;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use test_helper::drill::{parse_drill_output, DrillOutput};

use lxc_testcontainers::core::LxcContainerError;
use lxc_testcontainers::TestContainer;

#[test]
fn test_query_unknown_domain() -> Result<(), LxcContainerError> {
    TestContainer::new("local_koppeln".into()).with(|koppeln| {
        loop {
            let output = koppeln.exec(&|cmd| {
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

        TestContainer::new("local_drill".into()).with(|drill| {
            // TODO wait until ready
            std::thread::sleep(Duration::from_millis(3000));

            let dns_server = format!(
                "@{}",
                koppeln.get_ips().unwrap().first().unwrap().to_string()
            );
            let output = drill
                .exec(&|cmd| {
                    cmd.arg("drill")
                        .arg("unknown.dyn.example.com")
                        .arg(&dns_server)
                })
                .unwrap();

            let (_, drill) = parse_drill_output(std::str::from_utf8(&output.stdout).unwrap())
                .ok()
                .unwrap();

            assert_eq!(drill.answer, None);

            Ok(())
        })
    })
}


#[test]
fn test_set_ip_for_domain_name() -> Result<(), LxcContainerError> { 
    TestContainer::new("local_koppeln".into()).with(|koppeln| {
        std::thread::sleep(Duration::from_secs(1));

        // push default config file
        let mut config_src_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        config_src_path.push("tests/fixtures/base_config.toml");

        koppeln
            .file_push(&config_src_path, &"etc/koppeln/config.toml")
            .unwrap();

        // restart koppeln service
        koppeln
            .exec(&|cmd| cmd.arg("systemctl").arg("restart").arg("koppeln.service"))
            .expect("Could not restart koppeln service!");

        loop {
            let output = koppeln.exec(&|cmd| {
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
        // set IP via http
        let mut map = HashMap::new();
        map.insert("hostname", "test.dyn.example.com");
        map.insert("ip", "1.2.3.4");

        let dns_server = format!(
            "@{}",
            koppeln.get_ips().unwrap().first().unwrap().to_string()
        );

        let client = reqwest::blocking::Client::new();
        client
            .put(format!("http://{}/hostname", dns_server))
            .header("Authorization", "super_secure")
            .json(&map)
            .send()
            .expect("Could not set new IP address");

        TestContainer::new("local_drill".into()).with(|drill| {
            // TODO wait until ready
            std::thread::sleep(Duration::from_millis(3000));

            let output = drill
                .exec(&|cmd| {
                    cmd.arg("drill")
                        .arg("test.dyn.example.com")
                        .arg(&dns_server)
                })
                .unwrap();

            let (_, drill) = parse_drill_output(std::str::from_utf8(&output.stdout).unwrap())
                .ok()
                .unwrap();

            let answer = drill.answer.unwrap();
            assert_eq!(answer.domain_name, ".".to_string());
            assert_eq!(answer.ip, Ipv4Addr::new(1, 2, 3, 4));

            Ok(())
        })
    })
}

