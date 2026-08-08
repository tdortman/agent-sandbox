#![cfg(debug_assertions)]

mod support;
#[path = "transparent_suite/altsvc.rs"]
mod transparent_altsvc;
#[path = "transparent_suite/common.rs"]
mod transparent_common;
#[path = "transparent_suite/doh.rs"]
mod transparent_doh;
#[path = "transparent_suite/http.rs"]
mod transparent_http;
#[path = "transparent_suite/http3.rs"]
mod transparent_http3;
#[path = "transparent_suite/https.rs"]
mod transparent_https;
#[path = "transparent_suite/websocket.rs"]
mod transparent_websocket;
