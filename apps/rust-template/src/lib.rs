#[allow(warnings)]
mod bindings;
mod musigTest;
mod user;

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
        klave::router::add_user_transaction("create-user");
    }

    fn load_from_ledger(cmd: String){
        helloworld::hello_load_from_ledger(cmd);
    }

    fn insert_in_ledger(cmd: String){
        helloworld::hello_insert_in_ledger(cmd);
    }

    fn ping(cmd: String) {
        helloworld::hello_ping(cmd);
    }

    fn ping2() {
        klave::notifier::notify("pang2");
    }

    fn create_user(cmd:String){
        user::create_user(cmd);
    }
}

bindings::export!(Component with_types_in bindings);
