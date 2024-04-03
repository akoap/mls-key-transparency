use actix_web::{get, post, web, web::Payload, App, HttpServer, Responder};
use clap::Command;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

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

#[derive(Serialize, Deserialize)]
pub struct EpochHashSerializable {
    epoch: u64,
    digest: [u8; 32],
}

impl From<akd::helper_structs::EpochHash> for EpochHashSerializable {
    fn from(item: akd::helper_structs::EpochHash) -> Self {
        EpochHashSerializable {
            epoch: item.0,
            digest: item.1,
        }
    }
}

/// The AS state.
/// It holds the state for this application.
// TODO: See if this can be made private
pub struct ASData {
    directory: Mutex<Directory<Config, AsyncInMemoryDatabase, HardCodedAkdVRF>>,
}

impl ASData {
    fn init(input: Directory<Config, AsyncInMemoryDatabase, HardCodedAkdVRF>) -> Self {
        Self {
            directory: Mutex::new(input),
        }
    }
}

macro_rules! unwrap_item {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return actix_web::HttpResponse::PartialContent().finish(),
        }
    };
}

macro_rules! unwrap_data {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return actix_web::HttpResponse::InternalServerError().finish(),
        }
    };
}

macro_rules! unwrap_dir {
    ( $e:expr ) => {
        match $e {
            Some(x) => x,
            None => return actix_web::HttpResponse::InternalServerError().finish(),
        }
    };
}

macro_rules! unwrap_parse_json {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return actix_web::HttpResponse::BadRequest().finish(),
        }
    };
}

#[derive(Debug, Default, Serialize, Deserialize)]
enum ASHashAlgorithm {
    #[default]
    Sha256,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GetPubKeyRet {
    hash_algorithm: ASHashAlgorithm,
    public_key: Vec<u8>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AddUserInput {
    username: String,
    public_keys: Vec<Vec<u8>>,
}

// TODO: Try making private
#[derive(der::Sequence)]
pub struct AKDValueFormat {
    vec: Vec<asn1::Any>,
}

fn to_akd_value(input: &mut Vec<Vec<u8>>) -> Result<AkdValue> {
    let mut to_write = AKDValueFormat {
        vec: Vec::<asn1::Any>::new(),
    };
    for elem in input.iter() {
        to_write.vec.push(asn1::Any::from_der(&elem)?);
    }
    let result = to_write.to_der().unwrap();
    Ok(AkdValue(result))
}

// fn from_akd_value(input:&mut AkdValue) -> Result<Vec<Vec<u8>>> {
//     let fmt = AKDValueFormat::from_der(input.0)?;
//     let toRet = Vec::<Vec<u8>>::new();
//     for elem in fmt.vec.iter() {
//         toRet.append(asn1::write_single(&elem)?);
//     }
//     Ok(toRet)
// }

// === API ===

/// Registering a new client takes a serialised `ClientInfo` object and returns
/// a simple "Welcome {client name}" on success.
/// An HTTP conflict (409) is returned if a client with this name exists
/// already.
#[get("/public_key")]
async fn get_public_key_request<'a>(_body: Payload, data: web::Data<ASData>) -> impl Responder {
    // First get the correct public key
    let dir = data.directory.lock().unwrap();
    let pub_key_plain = unwrap_data!(dir.get_public_key().await).to_bytes();
    let pub_key_obj =
        unwrap_data!(unwrap_data!(VerifyingKey::from_bytes(&pub_key_plain)).to_public_key_der());
    let pub_key_der = pub_key_obj.as_bytes();
    let toRet = GetPubKeyRet {
        hash_algorithm: crate::ASHashAlgorithm::Sha256,
        public_key: pub_key_der.to_vec(),
    };
    actix_web::HttpResponse::Ok().json(toRet)
}
const MAX_SIZE: usize = 262_144; // max payload size is 256k

#[post("/add_user")]
async fn add_user<'a>(mut payload: Payload, data: web::Data<ASData>) -> impl Responder {
    // payload is a stream of Bytes objects
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = unwrap_item!(chunk);
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
            return actix_web::HttpResponse::BadRequest().finish();
        }
        body.extend_from_slice(&chunk);
    }

    // body is loaded, now we can deserialize serde-json
    let mut obj = unwrap_parse_json!(serde_json::from_slice::<AddUserInput>(&body));
    let toAdd = vec![(
        AkdLabel::from(&obj.username),
        unwrap_data!(to_akd_value(&mut obj.public_keys)),
    )];
    let dir = data.directory.lock().unwrap();
    let result = unwrap_data!(dir.publish(toAdd).await);
    actix_web::HttpResponse::Ok().json(EpochHashSerializable::from(result))
}

#[post("/{username}/update")]
async fn update_user<'a>(mut body: Payload, data: web::Data<ASData>) -> impl Responder {
    actix_web::HttpResponse::Ok().finish()
}

#[get("/{username}/lookup")]
async fn lookup_user<'a>(mut body: Payload, data: web::Data<ASData>) -> impl Responder {
    actix_web::HttpResponse::Ok().finish()
}

#[get("/{username}/history")]
async fn user_history<'a>(mut body: Payload, data: web::Data<ASData>) -> impl Responder {
    actix_web::HttpResponse::Ok().finish()
}

#[get("/audit")]
async fn audit_directory<'a>(mut body: Payload, data: web::Data<ASData>) -> impl Responder {
    actix_web::HttpResponse::Ok().finish()
}

// === Main function driving the AS ===

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::init();

    // Configure App and command line arguments.
    let matches = Command::new("OpenMLS DS")
        .version("0.1.0")
        .author("OpenMLS Developers")
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
            .service(update_user)
            .service(lookup_user)
            .service(user_history)
            .service(audit_directory)
    })
    .bind(addr)?
    .run()
    .await
}
