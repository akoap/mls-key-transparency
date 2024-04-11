use serde::{Deserialize, Serialize};
use akd::{HistoryProof, LookupProof};

pub mod serde_helpers {
    use hex::{FromHex, ToHex};
    use serde::Deserialize;

    /// A serde hex serializer for bytes
    pub fn bytes_serialize_hex<S, T>(x: &T, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: AsRef<[u8]>,
    {
        let hex_str = &x.as_ref().encode_hex_upper::<String>();
        s.serialize_str(hex_str)
    }

    /// A serde hex deserializer for bytes
    pub fn bytes_deserialize_hex<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: AsRef<[u8]> + FromHex,
        <T as FromHex>::Error: core::fmt::Display,
    {
        let hex_str = String::deserialize(deserializer)?;
        T::from_hex(hex_str).map_err(serde::de::Error::custom)
    }

}


// The EpochHash struct was not mads serializable by the creators of AKD, so we make an equivalent struct here that is serializable
#[derive(Serialize, Deserialize)]
pub struct EpochHashSerializable {
    pub epoch: u64,
    #[serde(serialize_with = "serde_helpers::bytes_serialize_hex")]
    #[serde(deserialize_with = "serde_helpers::bytes_deserialize_hex")]
    digest: [u8; 32],
}

// To make conversions from the akd struct to our struct easier, define this as a function (there's already a fairly simple mapping between mambers of the two structs)
impl From<akd::helper_structs::EpochHash> for EpochHashSerializable {
    fn from(item: akd::helper_structs::EpochHash) -> Self {
        EpochHashSerializable {
            epoch: item.0,
            digest: item.1,
        }
    }
}

// Tells the calling code what hash algorithm we are using
#[derive(Debug, Default, Serialize, Deserialize)]
pub enum ASHashAlgorithm {
    #[default]
    Sha256,
}

// The struct defining the output from the get public key endpoint
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GetPubKeyRet {
    pub hash_algorithm: ASHashAlgorithm,
    #[serde(serialize_with = "serde_helpers::bytes_serialize_hex")]
    #[serde(deserialize_with = "serde_helpers::bytes_deserialize_hex")]
    pub public_key: Vec<u8>, // DER encoded public key
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct PubKeyBuf(
    #[serde(serialize_with = "serde_helpers::bytes_serialize_hex")]
    #[serde(deserialize_with = "serde_helpers::bytes_deserialize_hex")]
    pub Vec<u8>
);

// The struct defining the input to the add user endpoint
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AddUserInput {
    pub username: String,
    pub public_keys: Vec<PubKeyBuf>, // Sequence of DER encoded public keys
}

// The struct defining the output from the lookup user endpoint
#[derive(Serialize, Deserialize)]
pub struct LookupUserRet{
    pub epoch_hash : EpochHashSerializable,
    pub proof : LookupProof
}

// The struct defining the output from the get user history endpoint
#[derive(Serialize, Deserialize)]
pub struct UserHistoryRet{
    pub epoch_hash : EpochHashSerializable,
    pub proof : HistoryProof
}


