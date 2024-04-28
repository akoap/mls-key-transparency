use serde::{Deserialize, Serialize};
use akd::{AkdValue, HistoryProof, LookupProof};
use der::asn1;
use ed25519_dalek::pkcs8::*;
use der::{Decode, Encode};


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
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct EpochHashSerializable {
    pub epoch: u64,
    #[serde(serialize_with = "serde_helpers::bytes_serialize_hex")]
    #[serde(deserialize_with = "serde_helpers::bytes_deserialize_hex")]
    pub digest: [u8; 32],
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

// Private struct used to serialize a vector of DER encoded public keys into one DER-encoded blob using the Sequence of functionality of the der library
#[derive(der::Sequence)]
pub struct AKDValueFormat {
    pub vec: Vec<asn1::Any>,
}

// Private struct defining the query parameters used to control the get user history endpoint
#[derive(Deserialize)]
pub struct HistoryParamsQuery {
    pub most_recent: usize,
    pub since_epoch: u64
}


// Override the default values to ensure the output is sane
impl Default for HistoryParamsQuery {
    fn default() -> Self {
        HistoryParamsQuery {
            most_recent: std::usize::MIN,
            since_epoch: std::u64::MAX
        }
    }
}

// Private struct defining the query parameters used to control the audit endpoint
#[derive(Serialize, Deserialize, Debug)]
pub struct AuditQuery {
    pub start_epoch: u64,
    pub end_epoch: u64
}


// Public function to convert a vector of DER encoded public keys into the Akd value used
pub fn to_akd_value(input: &mut Vec<PubKeyBuf>) -> Result<AkdValue> {
    // Initialize the helper struct defined above
    let mut to_write = AKDValueFormat {
        vec: Vec::<asn1::Any>::new(),
    };
    // Ierate through each public key in the input, convert it, and add it to the output
    for elem in input.iter() {
        to_write.vec.push(asn1::Any::from_der(&elem.0.as_ref())?);
    }
    // Convert from the helper struct to the final binary blob
    let result = to_write.to_der().unwrap();
    // Return the converted value
    Ok(AkdValue(result))
}

// Public function to convert a Akd value used into a vector of DER encoded public keys
pub fn from_akd_value(input:&mut AkdValue) -> Result<Vec<Vec<u8>>> {
    // Convert the binary blob to the helper struct above
    let fmt = AKDValueFormat::from_der(&input.0)?;
    // Initialize the return value
    let mut to_ret = Vec::<Vec<u8>>::new();
    // Cycle through every element in the helper struct and convert it to the output format, adding it to the return value
    for elem in fmt.vec.iter() {
        to_ret.push(elem.value().to_vec());
    }
    // Return the converted value
    Ok(to_ret)
}
