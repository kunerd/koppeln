use std::future::Future;
use warp::Filter;

pub fn create_update_server() -> impl Future<Output = ()> + 'static {
    // GET /hello/warp => 200 OK with body "Hello, warp!"
    //let hello = warp::path!("hello" / String).map(|name| format!("Hello, {}!", name));

    let hello = warp::any().map(|| "Hello World!");
    warp::serve(hello).bind(([0, 0, 0, 0], 3030))
}
