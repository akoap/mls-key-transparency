use reqwest::{self, blocking::Client, StatusCode};
use url::Url;

use serde::Serialize;

// TODO: return objects not bytes.

pub fn post(url: &Url, msg: &impl Serialize) -> Result<Vec<u8>, String> {
    let serialized_msg = serde_json::to_vec(msg).map_err(|e| format!("Error serializing message: {:?}", e))?;

    log::debug!("Post {:?}", url);
    log::trace!("Payload: {:?}", serialized_msg);

    let client = Client::new();
    let response = client
        .post(url.to_string())
        .body(serialized_msg)
        .send()
        .map_err(|e| format!("Error sending request: {:?}", e))?; // Handle request send error

    if response.status() != StatusCode::OK {
        return Err(format!("Error status code {:?}", response.status()));
    }

    response
        .bytes()
        .map(|bytes| bytes.into_iter().collect()) // Convert bytes to Vec<u8>
        .map_err(|e| format!("Error retrieving bytes from response: {:?}", e))
}

pub fn get(url: &Url) -> Result<Vec<u8>, String> {
    log::debug!("Get {:?}", url);
    let client = Client::new();
    let response = client.get(url.to_string()).send().map_err(|e| format!("Error sending request: {:?}", e))?; // Handle request send error

    if response.status() != StatusCode::OK {
        return Err(format!("Error status code {:?}", response.status()));
    }

    response
        .bytes()
        .map(|bytes| bytes.into_iter().collect()) // Convert bytes to Vec<u8>
        .map_err(|e| format!("Error retrieving bytes from response: {:?}", e))
}
