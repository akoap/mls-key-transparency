use std::sync::Mutex;
use actix_web::{get, post, web, App, HttpServer, Responder};
use url::Url;
use akd::{errors::AkdError, EpochHash};
use as_lib::{AuditQuery, EpochHashSerializable};
use reqwest::{self, StatusCode};
use clap::{Arg, Command};
use serde_qs;

type Config = akd::WhatsAppV1Configuration;

const AS_URL: &str = "http://localhost:8000";

struct AuditServiceData {
    previous_epoch_hash: Mutex<Option<EpochHash>>,
    audit_summary: Mutex<Result<(), AkdError>>,
    as_url: Url,
}

impl AuditServiceData {
    fn init() -> Self {
        Self {
            previous_epoch_hash: Mutex::new(None),
            audit_summary: Mutex::new(Ok(())),
            as_url: Url::parse(AS_URL).unwrap(),
        }
    }
}

#[post("/log_epoch")]
async fn log_epoch(json: web::Json<EpochHashSerializable>, data: web::Data<AuditServiceData>) -> impl Responder {
    log::debug!("Received epoch: {:?}", json);
    let new_epoch_hash = EpochHash(json.epoch, json.digest);
    let mut previous_epoch_hash = data.previous_epoch_hash.lock().unwrap();

    let previous_epoch = match &*previous_epoch_hash {
        Some(epoch) => { 
            log::debug!("Previous epoch: {:?}", epoch);
            epoch.clone()
        },
        None => {
            *previous_epoch_hash = Some(new_epoch_hash);
            return actix_web::HttpResponse::Ok().body(match &*data.audit_summary.lock().unwrap() {
                Ok(_) => { 
                    let result = "First epoch logged.";
                    log::debug!("{}", format!("{:?}", result));
                    String::from(result) 
                },
                Err(e) => {
                    log::debug!("Error: {:?}", e);
                    e.to_string()
                },
            });
        },
    };

    let mut url = data.as_url.clone();
    let audit_query = AuditQuery { start_epoch: previous_epoch.0, end_epoch: new_epoch_hash.0 };

    let query_string = serde_qs::to_string(&audit_query).unwrap();
    url.set_path("/audit");
    url.set_query(Some(&query_string));

    let response = reqwest::get(url).await;
    let audit_proof = match response {
        Ok(response) => { 
            if response.status() != StatusCode::OK {
                log::debug!("GET request to get audit proof failed, Error status code {:?}", response.status());
                return actix_web::HttpResponse::InternalServerError().body(format!("Error status code {:?}", response.status()));
            }
            match response.bytes().await {
                Ok(bytes) => serde_json::from_slice(bytes.as_ref()).unwrap(),
                Err(e) => {
                    log::debug!("Error retrieving bytes from response: {:?}", e);
                    return actix_web::HttpResponse::InternalServerError().body(format!("Error retrieving bytes from response: {:?}", e)) 
                },
            }
        },
        Err(e) => { 
            log::debug!("Error verifying audit proof: {:?}", e);
            return actix_web::HttpResponse::InternalServerError().body(format!("ERROR: {:?}", e)) 
        },
    };
    let audit_result = akd::auditor::audit_verify::<Config>(
        vec![previous_epoch.1, new_epoch_hash.1],
        audit_proof,
    ).await;

    *previous_epoch_hash = Some(new_epoch_hash);
    *data.audit_summary.lock().unwrap() = audit_result;

    actix_web::HttpResponse::Ok().body(match &*data.audit_summary.lock().unwrap() {
        Ok(_) => String::from("Audit verified."),
        Err(e) => e.to_string(),
    })
}

#[get("/audit")]
async fn audit(data: web::Data<AuditServiceData>) -> impl Responder {
    actix_web::HttpResponse::Ok().body(match &*data.audit_summary.lock().unwrap() {
        Ok(_) => String::from("Audit verified."),
        Err(e) => e.to_string(),
    })
}

#[get("/reset")]
async fn reset(data: web::Data<AuditServiceData>) -> impl Responder {
    let mut previous_epoch_hash = data.previous_epoch_hash.lock().unwrap();
    *previous_epoch_hash = None;
    let mut audit_summary = data.audit_summary.lock().unwrap();
    *audit_summary = Ok(());
    actix_web::HttpResponse::Ok().finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::init();

    // Configure App and command line arguments.
    let matches = Command::new("audit_service")
        .version("0.1.0")
        .about("PoC MLS Audit Service")
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("port")
                .help("Sets a custom port number"),
        )
        .get_matches();
    
    let data = web::Data::new(AuditServiceData::init());
    let port = matches.get_one("port").unwrap_or(&8100u16);
    let ip = "127.0.0.1";
    let addr = format!("{ip}:{port}");
    log::info!("Listening on: {}", addr);

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .service(log_epoch)
            .service(reset)
            .service(audit)
    })
    .bind(addr)?
    .run()
    .await
}
