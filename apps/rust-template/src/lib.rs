#[allow(warnings)]
mod bindings;

use bindings::Guest;
use klave;
//use serde_json::Value;
//use serde_json::json;
//use musig2::{AggNonce, SecNonce};

mod helloworld;
struct Component;

impl Guest for Component {

    fn register_routes(){
        klave::router::add_user_query("load-from-ledger");
        klave::router::add_user_transaction("insert-in-ledger");
        klave::router::add_user_query("ping");
        klave::router::add_user_query("ping2");
    }

    fn load_from_ledger(cmd: String){
        helloworld::hello_load_from_ledger(cmd);
    }

    fn insert_in_ledger(cmd: String){
        helloworld::hello_insert_in_ledger(cmd);
    }

    fn ping() {
        klave::notifier::notify("pong");
    }

    fn ping2() {
        klave::notifier::notify("pang2");
    }
}

bindings::export!(Component with_types_in bindings);
