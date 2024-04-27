use tls_codec::{Deserialize, TlsVecU16, TlsVecU32};
use url::Url;

use crate::networking::get_with_body_ds;

use super::{
    networking::{get_ds, post_ds, get_as, post_as},
    user::User,
    file_helpers
};

use as_lib::*;
use ds_lib::{
    messages::{
        AuthToken, PublishKeyPackagesRequest, RecvMessageRequest, RegisterClientRequest,
        RegisterClientSuccessResponse,
    },
    *,
};
use openmls::prelude::*;

pub struct Backend {
    ds_url: Url,
    as_url: Url,
}

impl Backend {
    /// Register a new client with the server.
    pub fn register_client(
        &self,
        key_packages: Vec<(Vec<u8>, KeyPackage)>,
    ) -> Result<AuthToken, String> {
        let mut url = self.ds_url.clone();
        url.set_path("/clients/register");

        let key_packages = ClientKeyPackages(
            key_packages
                .into_iter()
                .map(|(b, kp)| (b.into(), KeyPackageIn::from(kp)))
                .collect::<Vec<_>>()
                .into(),
        );
        let request = RegisterClientRequest { key_packages };
        let response_bytes = post_ds(&url, &request)?;
        let response =
            RegisterClientSuccessResponse::tls_deserialize(&mut response_bytes.as_slice())
                .map_err(|e| format!("Error decoding server response: {e:?}"))?;

        Ok(response.auth_token)
    }

    /// Get a list of all clients with name, ID, and key packages from the
    /// server.
    pub fn list_clients(&self) -> Result<Vec<Vec<u8>>, String> {
        let mut url = self.ds_url.clone();
        url.set_path("/clients/list");

        let response = get_ds(&url)?;
        match TlsVecU32::<Vec<u8>>::tls_deserialize(&mut response.as_slice()) {
            Ok(clients) => Ok(clients.into()),
            Err(e) => Err(format!("Error decoding server response: {e:?}")),
        }
    }

    /// Get and reserve a key package for a client.
    pub fn consume_key_package(&self, client_id: &[u8]) -> Result<KeyPackageIn, String> {
        let mut url = self.ds_url.clone();
        let path = "/clients/key_package/".to_string()
            + &base64::encode_config(client_id, base64::URL_SAFE);
        url.set_path(&path);

        let response = get_ds(&url)?;
        match KeyPackageIn::tls_deserialize(&mut response.as_slice()) {
            Ok(kp) => Ok(kp),
            Err(e) => Err(format!("Error decoding server response: {e:?}")),
        }
    }

    /// Publish client additional key packages
    pub fn publish_key_packages(&self, user: &User, ckp: ClientKeyPackages) -> Result<(), String> {
        let Some(auth_token) = user.auth_token() else {
            return Err("Please register user before publishing key packages".to_string());
        };
        let mut url = self.ds_url.clone();
        let path = "/clients/key_packages/".to_string()
            + &base64::encode_config(user.identity.borrow().identity(), base64::URL_SAFE);
        url.set_path(&path);

        let request = PublishKeyPackagesRequest {
            key_packages: ckp,
            auth_token: auth_token.clone(),
        };

        // The response should be empty.
        let _response = post_ds(&url, &request)?;
        Ok(())
    }

    /// Send a welcome message.
    pub fn send_welcome(&self, welcome_msg: &MlsMessageOut) -> Result<(), String> {
        let mut url = self.ds_url.clone();
        url.set_path("/send/welcome");

        // The response should be empty.
        let _response = post_ds(&url, welcome_msg)?;
        Ok(())
    }

    /// Send a group message.
    pub fn send_msg(&self, group_msg: &GroupMessage) -> Result<(), String> {
        let mut url = self.ds_url.clone();
        url.set_path("/send/message");

        // The response should be empty.
        let _response = post_ds(&url, group_msg)?;
        Ok(())
    }

    /// Get a list of all new messages for the user.
    pub fn recv_msgs(&self, user: &User) -> Result<Vec<MlsMessageIn>, String> {
        let Some(auth_token) = user.auth_token() else {
            return Err("Please register user before publishing key packages".to_string());
        };
        let mut url = self.ds_url.clone();
        let path = "/recv/".to_string()
            + &base64::encode_config(user.identity.borrow().identity(), base64::URL_SAFE);
        url.set_path(&path);

        let request = RecvMessageRequest {
            auth_token: auth_token.clone(),
        };

        let response = get_with_body_ds(&url, &request)?;
        match TlsVecU16::<MlsMessageIn>::tls_deserialize(&mut response.as_slice()) {
            Ok(r) => Ok(r.into()),
            Err(e) => Err(format!("Invalid message list: {e:?}")),
        }
    }

    /// Reset the DS.
    pub fn reset_server(&self) {
        let mut url = self.ds_url.clone();
        url.set_path("reset");
        get_ds(&url).unwrap();
        file_helpers::delete_files_with_prefix("openmls_cli").expect("Error deleting files with prefix openmls_cli");
    }

    // Add user to AKD
    pub fn add_user_akd(
        &self,
        add_user_input: &AddUserInput,
    ) -> Result<EpochHashSerializable, String> {
        let mut url = self.as_url.clone();
        url.set_path("add_user");
        let response = post_as(&url, add_user_input)?;
        match serde_json::from_slice::<EpochHashSerializable>(&response) {
            Ok(r) => Ok(r),
            Err(e) => Err(format!("Error decoding server response: {e:?}")),
        }
    }

    // Lookup user key in AKD
    pub fn lookup_user(&self, user: &User) -> Result<LookupUserRet, String> {
        let mut url = self.as_url.clone();
        let path = "/".to_string()
            + &base64::encode_config(user.identity.borrow().identity(), base64::URL_SAFE)
            + "/lookup";
        url.set_path(&path);
        let response = get_as(&url)?;
        match serde_json::from_slice::<LookupUserRet>(&response) {
            Ok(r) => Ok(r),
            Err(e) => Err(format!("Error decoding server response: {e:?}")),
        }
    }

    // Get public key of server
    pub fn get_public_key(&self) -> Result<GetPubKeyRet, String> {
        let mut url = self.as_url.clone();
        url.set_path("public_key");
        let response = get_as(&url)?;
        match serde_json::from_slice::<GetPubKeyRet>(&response) {
            Ok(r) => Ok(r),
            Err(e) => Err(format!("Error decoding server response: {e:?}")),
        }
    }
}

impl Default for Backend {
    fn default() -> Self {
        Self {
            // There's a public DS at https://mls.franziskuskiefer.de
            ds_url: Url::parse("http://localhost:8080").unwrap(),
            as_url: Url::parse("http://localhost:8000").unwrap(),
        }
    }
}
