use koppeln::settings::Settings;
use koppeln::{Storage, dns, web};

use config::ConfigError;
use env_logger::Env;

use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<(), ConfigError> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let settings = Settings::load()?;
    log::debug!("Settings loaded:\n{:?}", settings);

    let storage = Arc::new(Mutex::new(Storage::new(
        settings.dns.soa.mname.clone(),
        settings.addresses,
    )));

    let update_server = tokio::spawn(web::create_update_server(
        settings.http,
        Arc::clone(&storage),
    ));

    let dns_server = dns::Server::new(settings.dns, storage);

    let dns_server = tokio::spawn(dns_server.run(settings.user, settings.group));

    futures::future::try_join(update_server, dns_server)
        .await
        .unwrap();

    Ok(())
}
