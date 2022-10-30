use std::convert::Infallible;
use std::net::{SocketAddr, IpAddr};
use std::future::Future;

use warp;
use warp::Filter;
use warp::http::StatusCode;
use serde::Deserialize;

use super::AddressStorage;

#[derive(Debug, Deserialize, Clone)]
pub struct UpdateInfo {
    pub hostname: String,
    pub ip: IpAddr,
}

pub fn create_update_server(address: SocketAddr, storage: AddressStorage) -> impl Future<Output = ()> + 'static {
    warp::serve(update_address(storage)).bind(address)
}

pub fn update_address(
    storage: AddressStorage,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("hostname")
        .and(warp::put())
        .and(with_token())
        .and(json_body())
        .and(with_storage(storage))
        .and_then(update_address_handler)
        .recover(handle_missing_auth_header)
}

async fn handle_missing_auth_header(rejection: warp::Rejection) -> Result<impl warp::Reply, warp::Rejection> {
    if rejection.find::<warp::reject::MissingHeader>().is_some() {
        Ok(StatusCode::UNAUTHORIZED)
    } else {
        Err(rejection)
    }
}

fn with_token() -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    warp::header("authorization")
}

fn with_storage(storage: AddressStorage) -> impl Filter<Extract = (AddressStorage,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || storage.clone())
}

fn json_body() -> impl Filter<Extract = (UpdateInfo,), Error = warp::Rejection> + Clone {
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

pub async fn update_address_handler(token: String, update_info: UpdateInfo, storage: AddressStorage) -> Result<impl warp::Reply, Infallible> {
    let mut addresses = storage.lock().await;
    let mut addr = addresses.get_mut(&update_info.hostname).unwrap();

    if token != addr.token {
        return Ok(StatusCode::FORBIDDEN);
    }
    
    match update_info.ip {
        IpAddr::V4(ipv4) => addr.ipv4 = Some(ipv4),
        IpAddr::V6(ipv6) => addr.ipv6 = Some(ipv6)
    }

    Ok(StatusCode::NO_CONTENT)
}
