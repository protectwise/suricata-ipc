//! Crate that can act as a suricata plugin that buffers data for sending via uds
#![deny(missing_docs, unused, dead_code, non_snake_case)]

use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;

use suricata::conf::ConfNode;
use suricata::SCLogError;

mod client;
mod errors;

use client::{Client, Config};
pub use errors::Error;

/// Creates a logging client that writes to kafka. Configuration parameters will be located in the
/// 'kafka' section in the suricata.yaml
#[no_mangle]
pub extern "C" fn create_logging_client(conf: *const c_void) -> *mut Client {
    let conf = ConfNode::wrap(conf);

    let brokers = if let Some(val) = conf.get_child_value("brokers") {
        val.to_string()
    } else {
        SCLogError!("'brokers' parameter required");
        return std::ptr::null_mut();
    };

    let topic = if let Some(val) = conf.get_child_value("brokers") {
        val.to_string()
    } else {
        SCLogError!("'brokers' parameter required");
        return std::ptr::null_mut();
    };

    let in_flight_messages = conf
        .get_child_value("in_flight_messages")
        .map(|str_val| str_val.parse::<usize>().ok())
        .flatten()
        .unwrap_or(1024);

    let config = Config {
        brokers: brokers,
        topic: topic,
        in_flight_messages: in_flight_messages,
    };

    match smol::block_on(Client::new(config)) {
        Ok(cli) => Box::into_raw(Box::new(cli)),
        Err(e) => {
            SCLogError!("Unable to create client: {:?}", e);
            std::ptr::null_mut()
        }
    }

}

/// Copy the message into our memory space and forward to the logging client
#[no_mangle]
pub extern "C" fn send_to_logging_client(
    buffer: *const c_char,
    buffer_len: c_int,
    client: *mut Client,
) -> c_int {
    if buffer == std::ptr::null() {
        SCLogError!("Unable to send message to client: buffer was null");
        return 1;
    }
    if client == std::ptr::null_mut() {
        SCLogError!("Unable to send message to client: client was null");
        return 1;
    }
    let buffer_len = buffer_len as usize;
    let buffer = buffer as *const u8;

    let message = unsafe { std::slice::from_raw_parts(buffer, buffer_len).to_vec() }.to_vec();

    let client: Box<Client> = unsafe { Box::from_raw(client) };
    let res = smol::block_on(client.send(message));

    std::mem::forget(client);

    if let Err(e) = res {
        SCLogError!("Unable to send message to client: {:?}", e);
        1
    } else {
        0
    }
}

/// Releases the logging client
#[no_mangle]
pub extern "C" fn release_logging_client(client: *mut Client) {
    if client != std::ptr::null_mut() {
        let client: Box<Client> = unsafe { Box::from_raw(client) };

        if let Err(e) = smol::block_on(client.close()) {
            SCLogError!("Error closing client: {:?}", e);
        }
    }
}
