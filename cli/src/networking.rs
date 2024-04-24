use ds_lib::messages::AuthToken;
use reqwest::{self, blocking::Client, StatusCode};
use serde_json::json;
use url::Url;

use openmls::prelude::tls_codec;
use serde;

// TODO: return objects not bytes.

pub fn post_ds(url: &Url, msg: &impl tls_codec::Serialize) -> Result<Vec<u8>, String> {
    let serialized_msg = msg.tls_serialize_detached().unwrap();
    log::debug!("Post {:?}", url);
    log::trace!("Payload: {:?}", serialized_msg);
    let client = Client::new();
    let response = client.post(url.to_string()).body(serialized_msg).send();
    if let Ok(r) = response {
        if r.status() != StatusCode::OK {
            return Err(format!("Error status code {:?}", r.status()));
        }
        match r.bytes() {
            Ok(bytes) => Ok(bytes.as_ref().to_vec()),
            Err(e) => Err(format!("Error retrieving bytes from response: {e:?}")),
        }
    } else {
        Err(format!("ERROR: {:?}", response.err()))
    }
}

pub fn get_ds(url: &Url) -> Result<Vec<u8>, String> {
    let auth_token_option: Option<&AuthToken> = None;
    get_internal_ds(url, auth_token_option)
}

pub fn get_with_body_ds(url: &Url, body: &impl tls_codec::Serialize) -> Result<Vec<u8>, String> {
    get_internal_ds(url, Some(body))
}

fn get_internal_ds(url: &Url, msg: Option<&impl tls_codec::Serialize>) -> Result<Vec<u8>, String> {
    log::debug!("Get {:?}", url);
    let client = Client::new().get(url.to_string());
    let client = if let Some(msg) = msg {
        let serialized_msg = msg.tls_serialize_detached().unwrap();
        log::trace!("Payload: {:?}", serialized_msg);
        client.body(serialized_msg)
    } else {
        client
    };
    let response = client.send();
    if let Ok(r) = response {
        if r.status() != StatusCode::OK {
            return Err(format!("Error status code {:?}", r.status()));
        }
        match r.bytes() {
            Ok(bytes) => Ok(bytes.as_ref().to_vec()),
            Err(e) => Err(format!("Error retrieving bytes from response: {e:?}")),
        }
    } else {
        Err(format!("ERROR: {:?}", response.err()))
    }
}

pub fn post_as(url: &Url, msg: &impl serde::Serialize) -> Result<Vec<u8>, String> {
    log::debug!("Post {:?}", url);
    // log::debug!("Payload: {:?}", serialized_msg);

    let client = Client::new();
    let response = client
        .post(url.to_string())
        .json(&msg)
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

pub fn get_as(url: &Url) -> Result<Vec<u8>, String> {
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
