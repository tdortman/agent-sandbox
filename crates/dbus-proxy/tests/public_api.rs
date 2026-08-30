//! Public-API behaviour tests for the D-Bus relay library.
//!
//! Exercises target extraction and relay configuration construction against
//! the `agent_sandbox_dbus_proxy` interface.
use std::path::PathBuf;

use agent_sandbox_core::{DbusBus, DbusMessageKind};
use agent_sandbox_dbus_proxy::{RelayConfig, target_from_message};
use zbus::message::Message;

#[test]
fn relay_config_new_preserves_socket_endpoints_and_defaults() {
    let config = RelayConfig::new("/tmp/listen.sock", "unix:path=/tmp/bus", "/tmp/policy.sock");
    assert_eq!(config.listen, PathBuf::from("/tmp/listen.sock"));
    assert_eq!(config.upstream_address, "unix:path=/tmp/bus");
    assert_eq!(config.policy_socket, PathBuf::from("/tmp/policy.sock"));
    assert_eq!(config.bus, DbusBus::Session);
}

#[test]
fn target_from_message_extracts_method_call_identity() {
    let message = Message::method_call("/org/example/Object", "Ping")
        .expect("message builder")
        .destination("org.example.Service")
        .expect("destination")
        .interface("org.example.Interface")
        .expect("interface")
        .build(&())
        .expect("message build");

    let target = target_from_message(&message, DbusBus::Session);
    assert_eq!(target.bus, DbusBus::Session);
    assert_eq!(target.destination, "org.example.Service");
    assert_eq!(target.object_path, "/org/example/Object");
    assert_eq!(target.interface, "org.example.Interface");
    assert_eq!(target.member, "Ping");
    assert_eq!(target.message_kind, DbusMessageKind::MethodCall);
}
