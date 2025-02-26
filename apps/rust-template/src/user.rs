use std::f32::consts::E;

use klave;
use klave::crypto::subtle::EcKeyGenParams;
use klave::crypto::subtle::GenAlgorithm;
use serde_json::Value;
use serde_json::json;

pub fn create_user(cmd: String){
    let Ok(v) = serde_json::from_str::<Value>(&cmd) else {
        klave::notifier::notify_error(&format!("failed to parse '{}' as json", cmd));
        return
    };
    let Ok(connector_key) = klave::context::get("sender") else {
        klave::notifier::notify_error("failed to get the sender");
        return
    };
    let Ok(user) = klave::ledger::get_table("users").get(&connector_key) else {
        klave::notifier::notify_error(&format!("failed to read '{}' from ledger", connector_key));
        return
    };
    if (!user.is_empty())
    {
        klave::notifier::notify_error("User associated with this context key has already been created");
        return
    };

    //create ECC key
    let ec_params = EcKeyGenParams {
        namedCurve: "secp256k1".to_string()
    };
    let algo = GenAlgorithm::EcKeyGenParams(ec_params);
    let Ok(user_key) = klave::crypto::subtle::generate_key(&algo, true, &["sign","verify"]) else {
        klave::notifier::notify_error("failed to create secp256k1 key");
        return
    };
    let Ok(()) = klave::crypto::subtle::save_key(&user_key, &connector_key) else {
        klave::notifier::notify_error("failed to save secp256k1 key");
        return
    };
    let Ok(buffer) = klave::crypto::subtle::export_key("raw", &user_key) else {
        klave::notifier::notify_error("failed to export secp256k1 key");
        return
    };
    let Ok(s) = String::from_utf8(buffer) else {
        klave::notifier::notify_error("failed to convert buffer in string");
        return
    };

    match klave::ledger::get_table("users").set(&connector_key, &connector_key) {
        Err(e) => {
            klave::notifier::notify_error(&format!("failed to write to ledger: '{}'", e));
            // sdk::cancel_transaction();
            return
        }
        _ => {}
    }

    let result_as_json = json!({
        "inserted": true,
        "key": s
        });
    klave::notifier::notify(&result_as_json.to_string());

}