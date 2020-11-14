use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;
use tokio::net::UdpSocket;

use hyper::{body::HttpBody as _, Body, Client, Request, Uri};
use spectral::prelude::*;
use testcontainers::core::Port;
use testcontainers::*;
use trust_dns_client::client::{Client as DnsClient, ClientHandle, AsyncClient};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_client::udp::UdpClientStream;

#[derive(Default)]
struct TestServer;

// TODO replace with GenericImage
impl Image for TestServer {
    type Args = Vec<String>;
    type EnvVars = HashMap<String, String>;
    type Volumes = HashMap<String, String>;
    type EntryPoint = std::convert::Infallible;

    fn descriptor(&self) -> String {
        String::from("dyndns-debian:latest")
    }

    fn wait_until_ready<D: Docker>(&self, container: &Container<D, Self>) {
        container
            .logs()
            .stderr
            .wait_for_message("DNS server now listening")
            .unwrap();
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

    fn ports(&self) -> Option<Vec<Port>> {
        let mut ports: Vec<Port> = Vec::new();
        ports.push(Port {
            local: 8080,
            internal: 80,
        });
        ports.push((5353, 53).into());

        Some(ports)
    }

    fn with_args(self, _arguments: <Self as Image>::Args) -> Self {
        self
    }
}

//#[test]
#[tokio::test]
async fn should_get_the_correct_ipv4() {
    let _ = pretty_env_logger::try_init();
    let docker = clients::Cli::default();

    let container = docker.run(TestServer);

    let client = Client::new();
    let req = Request::builder()
        .method("PUT")
        .uri("http://localhost:8080/hostname")
        .header("Authorization", "super_secure")
        .body(Body::from(
            "{\"hostname\":\"test.dyn.example.com\", \"ip\":\"12.13.14.15\"}",
        ))
        .expect("request builder");
    let res = client.request(req).await.expect("http request");
    println!("status: {}", res.status());

    let address = "127.0.0.1:5353".parse().unwrap();
    let stream = UdpClientStream::<UdpSocket>::new(address);
    //let (mut client, bg) = runtime.block_on(client).expect("connection failed");
    let (mut client, bg) = AsyncClient::connect(stream).await.expect("connection failed");

    let name = Name::from_str("test.dyn.example.com.").unwrap();
    let response = client.query(name, DNSClass::IN, RecordType::A).await.unwrap();
    let answers: &[Record] = response.answers();
    if let &RData::A(ref ip) = answers[0].rdata() {
        assert_eq!(*ip, Ipv4Addr::new(12, 13, 14, 15))
    } else {
        assert!(false, "unexpected result")
    }
}
