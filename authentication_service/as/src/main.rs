use actix_web::{get, post, web, App, HttpServer, Responder};
use clap::Command;
use serde::Deserialize;
use std::sync::Mutex;

use as_lib::*;
use akd::directory::Directory;
use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::storage::StorageManager;
use akd::{AkdLabel, AkdValue};
use der::asn1;
use der::{Decode, Encode};
use ed25519_dalek::pkcs8::*;
use ed25519_dalek::*;


type Config = akd::WhatsAppV1Configuration;

/// The AS state.
/// It holds the state for this application.
struct ASData {
    directory: Mutex<Directory<Config, AsyncInMemoryDatabase, HardCodedAkdVRF>>,
}

// Creates an instance of the struct given the directory as an argument
impl ASData {
    fn init(input: Directory<Config, AsyncInMemoryDatabase, HardCodedAkdVRF>) -> Self {
        Self {
            directory: Mutex::new(input),
        }
    }
}

// Simplifies the error handling within the functions that can just return an internal server error
macro_rules! unwrap_data {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return actix_web::HttpResponse::InternalServerError().finish(),
        }
    };
}

// Private struct used to serialize a vector of DER encoded public keys into one DER-encoded blob using the Sequence of functionality of the der library
#[derive(der::Sequence)]
struct AKDValueFormat {
    vec: Vec<asn1::Any>,
}

// Private struct defining the query parameters used to control the get user history endpoint
#[derive(Deserialize)]
struct HistoryParamsQuery {
    most_recent:usize,
    since_epoch:u64
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
#[derive(Deserialize)]
struct AuditQuery {
    start_epoch:u64,
    end_epoch:u64
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

// === API ===

#[get("/public_key")]
async fn get_public_key_request<'a>(data: web::Data<ASData>) -> impl Responder {
    // First get the correct public key
    let dir = data.directory.lock().unwrap();
    let pub_key_plain = unwrap_data!(dir.get_public_key().await).to_bytes();
    // Then we need to do multiple steps to convert it to the correct format (warning: rearranging this into fewer lines might cause it not to compile)
    let pub_key_obj =
        unwrap_data!(unwrap_data!(VerifyingKey::from_bytes(&pub_key_plain)).to_public_key_der());
    let pub_key_der = pub_key_obj.as_bytes();
    // Set up the output structure to serialize
    let to_ret = GetPubKeyRet {
        hash_algorithm: crate::ASHashAlgorithm::Sha256,
        public_key: pub_key_der.to_vec(),
    };
    // Return the serialized output
    actix_web::HttpResponse::Ok().json(to_ret)
}

 // This is also used for updating a user
#[post("/add_user")]
async fn add_user<'a>(mut json: web::Json<AddUserInput>, data: web::Data<ASData>) -> impl Responder {
    // Format the input key-value pairs are supposed to be in (taken straight from docs)
    let to_add = vec![(
        AkdLabel::from(&json.username),
        unwrap_data!(to_akd_value(&mut json.public_keys)),
    )];
    // Add this to the directory and return the serialized output
    let dir = data.directory.lock().unwrap();
    let result = unwrap_data!(dir.publish(to_add).await);
    actix_web::HttpResponse::Ok().json(EpochHashSerializable::from(result))
}

#[get("/{username}/lookup")]
async fn lookup_user<'a>(path: web::Path<String>, data: web::Data<ASData>) -> impl Responder {
    // The username we get from the url used (not sure if this handles url encoding)
    let username = path.into_inner();
    // Perform the lookup, format the output, and return it
    let dir = data.directory.lock().unwrap();
    let (proof, hash) = unwrap_data!(dir.lookup(AkdLabel::from(&username)).await);
    let to_ret = LookupUserRet {
        epoch_hash: EpochHashSerializable::from(hash),
        proof : proof,
    };
    actix_web::HttpResponse::Ok().json(to_ret)
}

#[get("/{username}/history")]
async fn user_history<'a>(path: web::Path<String>, query: web::Query<HistoryParamsQuery>, data: web::Data<ASData>) -> impl Responder {
    // The username we get from the url used (not sure if this handles url encoding)
    let username = path.into_inner();
    // Since the HistoryParams enum was not made serializable, we use query parameters instead of it
    let mut params = akd::directory::HistoryParams::Complete;
    // If most recent query parameter was set, use it
    if query.most_recent != std::usize::MIN {
        params = akd::directory::HistoryParams::MostRecent(query.most_recent)
    // Otherwise if the since epoch query parameter was set, use it
    } else if query.since_epoch != std::u64::MAX {
        params = akd::directory::HistoryParams::SinceEpoch(query.since_epoch)
    }
    // Perform the lookup, format the output, and return it
    let dir = data.directory.lock().unwrap();
    let (proof, hash) = unwrap_data!(dir.key_history(&AkdLabel::from(&username), params).await);
    let to_ret = UserHistoryRet {
        epoch_hash : EpochHashSerializable::from(hash),
        proof : proof,
    };
    actix_web::HttpResponse::Ok().json(to_ret)
}

#[get("/audit")]
async fn audit_directory<'a>(mut query: web::Query<AuditQuery>, data: web::Data<ASData>) -> impl Responder {
    // For this one we use the parameters and/or their defaults mostly as-is, but we automatically adjust an unset max epoch value to the largest valid value to avoid making the user worry about the current epoch value
    // Since the max allowable epoch value requires an api query, set ourselves up here
    let dir = data.directory.lock().unwrap();
    // Perform the necessary adjustment
    if query.end_epoch == std::u64::MAX {
        query.end_epoch = unwrap_data!(dir.get_epoch_hash().await).0;
    }
    // get the proof and return it after serializing
    let result = unwrap_data!(dir.audit(query.start_epoch, query.end_epoch).await);
    actix_web::HttpResponse::Ok().json(result)
}

// === Main function driving the AS ===
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::init();

    // Configure App and command line arguments.
    let matches = Command::new("OpenMLS+AKD AS")
        .version("0.1.0")
        .author("Mihir Rajpal")
        .about("PoC MLS Authentication Service")
        .arg(
            clap::Arg::new("port")
                .short('p')
                .long("port")
                .value_name("port")
                .help("Sets a custom port number"),
        )
        .get_matches();

    // The data this app operates on.
    // TODO: Fine tune configuration, storage, and VRF
    let database: AsyncInMemoryDatabase = AsyncInMemoryDatabase::new();
    let storage_manager: StorageManager<AsyncInMemoryDatabase> =
        StorageManager::new_no_cache(database);
    let vrf: HardCodedAkdVRF = HardCodedAkdVRF {};
    let directory: Directory<Config, AsyncInMemoryDatabase, HardCodedAkdVRF> =
        Directory::<Config, _, _>::new(storage_manager, vrf)
            .await
            .expect("Could not create AKD directory.");
    let data = web::Data::new(ASData::init(directory));

    // Set default port or use port provided on the command line.
    let port = matches.get_one("port").unwrap_or(&8000u16);

    let ip = "127.0.0.1";
    let addr = format!("{ip}:{port}");
    log::info!("Listening on: {}", addr);

    // Start the server.
    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .service(get_public_key_request)
            .service(add_user)
            .service(lookup_user)
            .service(user_history)
            .service(audit_directory)
    })
    .bind(addr)?
    .run()
    .await
}
