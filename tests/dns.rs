use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;
use tokio::net::UdpSocket;

use spectral::prelude::*;
use testcontainers::{core::{PortMapping, WaitFor}, *};
use trust_dns_client::client::{Client as DnsClient, ClientHandle, AsyncClient};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_client::udp::UdpClientStream;

#[derive(Default)]
struct TestServer;

impl Image for TestServer {
    type Args = Vec<String>;
    type EnvVars = HashMap<String, String>;
    type Volumes = HashMap<String, String>;
    type EntryPoint = std::convert::Infallible;

    fn descriptor(&self) -> String {
        String::from("dyndns-debian:latest")
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        //vec![WaitFor::message_on_stdout("DNS server now listening")]
        vec![WaitFor::message_on_stderr("DNS server now listening")]
    }

    fn args(&self) -> <Self as Image>::Args {
        vec![]
    }

    fn volumes(&self) -> Self::Volumes {
        let mut volumes = HashMap::new();
        let project_root = env!("CARGO_MANIFEST_DIR");
        volumes.insert(format!("{}/config", project_root).to_string(), "/etc/dyndns/config".to_string());
        volumes
    }

    fn env_vars(&self) -> Self::EnvVars {
        let mut env: HashMap<String, String> = HashMap::new();
        env.insert("RUN_MODE".into(), "test".into());
        env
    }

    fn with_args(self, _: <Self as Image>::Args) -> Self {
        self
    }
}

//#[test]
#[tokio::test]
async fn should_get_the_correct_ipv4() {
    let _ = pretty_env_logger::try_init();
    let docker = clients::Cli::default();

    println!("container starting");
    let container = docker.run_with_args(
        TestServer,
        RunArgs::default()
            .with_mapped_port(PortMapping::Udp{local: 5453, internal: 53})
            .with_mapped_port(PortMapping::Tcp{local: 8080, internal: 80})
    );

    let host_port = container.get_host_port(80);

    println!("containe running: {}", host_port);

    let mut map = HashMap::new();
    map.insert("hostname", "test.dyn.example.com");
    map.insert("ip", "12.13.14.15");

    let client = reqwest::Client::new();
    let res = client.put("http://localhost:8080/hostname")
        .header("Authorization", "super_secure")
        .json(&map)
        .send()
        .await
    .unwrap();

    println!("status: {}", res.status());

    //let stream = UdpClientStream::<UdpSocket>::new(([127, 0, 0, 1], 5453).into());
    let stream = UdpClientStream::<UdpSocket>::new(([8, 8, 8, 8], 53).into());
    //let (mut client, bg) = runtime.block_on(client).expect("connection failed");
    let (mut client, bg) = AsyncClient::connect(stream).await.expect("connection failed");

    //let name = Name::from_str("test.dyn.example.com.").unwrap();
    let name = Name::from_str("www.example.com.").unwrap();
    println!("{:?}", name);
    let query = client.query(name, DNSClass::IN, RecordType::A);
    let response = query.await.unwrap();
    println!("{:?}", response);
    let answers: &[Record] = response.answers();
    if let &RData::A(ref ip) = answers[0].rdata() {
        assert_eq!(*ip, Ipv4Addr::new(12, 13, 14, 15))
    } else {
        assert!(false, "unexpected result")
    }
}
