use koppeln::settings::Settings;
use koppeln::{Storage, dns, web};

use config::ConfigError;
use env_logger::Env;
use futures::SinkExt;
use futures::stream::StreamExt;
use koppeln::dns::{NotImplementedResponse, codec};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<(), ConfigError> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let settings = Settings::load()?;
    log::debug!("Settings loaded:\n{:?}", settings);

    let storage = Arc::new(Mutex::new(Storage::new(
        settings.soa.mname.clone(),
        settings.addresses,
    )));

    let web_server_address = SocketAddr::from((settings.web_address, settings.web_port));
    let update_server = tokio::spawn(web::create_update_server(
        web_server_address,
        storage.clone(),
    ));
    log::info!(
        "HTTP server now listening on: {ip}:{port}",
        ip = settings.web_address,
        port = settings.web_port
    );

    let addr = SocketAddr::from((settings.dns_address, settings.dns_port));
    let udp_socket = UdpSocket::bind(&addr).await.unwrap();
    let mut dns_stream = UdpFramed::new(udp_socket, dns::Codec);

    log::info!(
        "DNS server now listening on: {ip}:{port}",
        ip = settings.dns_address,
        port = settings.dns_port
    );

    let udp_server = tokio::spawn(async move {
        log::debug!("Waiting for DNS queries...");
        while let Some(res) = dns_stream.next().await {
            let (query, addr) = match res {
                Ok((query, addr)) => (query, addr),
                Err(err) => {
                    log::error!("{err}");
                    continue;
                }
            };
            log::debug!("DNS message received: {:?}", query);

            let response = match query {
                dns::Request::StandardQuery(query) => {
                    let records = match storage.lock() {
                        Ok(storage) => storage,
                        Err(err) => {
                            log::error!("failed to lock storage: {err}");
                            continue;
                        }
                    };
                    let msg = dns::server::handle_standard_query(&settings.soa, &records, query);
                    codec::Response::StandardQuery(msg)
                }
                dns::Request::Unsupported(header) => heandle_unsupported(header),
            };

            log::debug!("DNS response: {:?}", response);
            dns_stream.send((response, addr)).await.unwrap();
        }
    });

    futures::future::try_join(update_server, udp_server)
        .await
        .unwrap();

    Ok(())
}

fn heandle_unsupported(header: dns::Header) -> codec::Response {
    let header = dns::Header {
        authoritative_answer: true,
        truncated: false,
        recursion_available: false,
        an_count: 0,
        response_code: dns::ResponseCode::NotImplemented,
        ..header
    };
    codec::Response::NotImplemented(NotImplementedResponse { header })
}
