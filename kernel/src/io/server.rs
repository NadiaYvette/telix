//! Server event loop — blocking recv loop dispatching to a handler.

use crate::ipc::Message;
use crate::ipc::port::{self, PortId};

/// Run a server event loop: block on the given port and dispatch
/// each message to the handler function.
/// The handler receives the port ID the message arrived on and the message.
#[allow(dead_code)]
pub fn server_loop(service_port: PortId, handler: fn(PortId, Message)) -> ! {
    loop {
        match port::recv(service_port) {
            Ok(msg) => handler(service_port, msg),
            Err(()) => {
                // Port was destroyed — shut down.
                break;
            }
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
