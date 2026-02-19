use koppeln::settings::Settings;
use koppeln::{Storage, dns, web};

use config::ConfigError;
use env_logger::Env;

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
        Arc::clone(&storage),
    ));
    log::info!(
        "HTTP server now listening on: {ip}:{port}",
        ip = settings.web_address,
        port = settings.web_port
    );

    let dns_server = dns::Server {
        soa: settings.soa,
        storage,
        listen_addr: settings.dns_address,
        listen_port: settings.dns_port,
    };

    let dns_server = tokio::spawn(dns_server.run());

    futures::future::try_join(update_server, dns_server)
        .await
        .unwrap();

    Ok(())
}
