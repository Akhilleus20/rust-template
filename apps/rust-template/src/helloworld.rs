use serde_json::Value;
use serde_json::json;

pub fn hello_load_from_ledger(cmd: String){
    let Ok(v) = serde_json::from_str::<Value>(&cmd) else {
        klave::notifier::notify_error(&format!("failed to parse '{}' as json", cmd));
        return
    };
    let key = v["key"].as_str().unwrap();
    let Ok(res) = klave::ledger::get_table("my_table").get(key) else {
        klave::notifier::notify_error(&format!("failed to read from ledger: '{}'", cmd));
        return
    };
    let msg = if res.is_empty() {
        format!("the key '{}' was not found in table my_table", cmd)
    } else {
        let result_as_json = json!({
            "value": res,
        });
        format!("{}", result_as_json.to_string())
    };
    klave::notifier::notify(&msg);
}

#[allow(dead_code)]
pub fn hello_insert_in_ledger(cmd: String){
    let Ok(v) = serde_json::from_str::<Value>(&cmd) else {
        klave::notifier::notify_error(&format!("failed to parse '{}' as json", cmd));
        // klave:: cancel_transaction();
        return
    };
    let key = v["key"].as_str().unwrap();
    let value = v["value"].as_str().unwrap();
    match klave::ledger::get_table("my_table").set(key, value) {
        Err(e) => {
            klave::notifier::notify_error(&format!("failed to write to ledger: '{}'", e));
            // sdk::cancel_transaction();
            return
        }
        _ => {}
    }

    let result_as_json = json!({
        "inserted": true,
        "key": key,
        "value": value
        });
    klave::notifier::notify(&result_as_json.to_string());
}