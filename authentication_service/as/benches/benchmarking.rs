use std::time::Duration;

use as_lib::{AddUserInput, AuditQuery, HistoryParamsQuery, PubKeyBuf};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ed25519_dalek::{pkcs8::EncodePublicKey, VerifyingKey};
use reqwest;
use serde_qs;
use url::Url;

pub fn bench_get_public_key_request(c: &mut Criterion) {
    let client = reqwest::blocking::Client::new();
    c.bench_function("get_public_key_request", |b| b.iter(|| {
        let res = client.get("http://localhost:8000/public_key").send();
        let body = res.unwrap().text().unwrap();
        black_box(body);
    }));
}

pub fn bench_lookup_user(c: &mut Criterion) {
    let client = reqwest::blocking::Client::new();
    let public_key_32: [u8; 32] = [0; 32];
    let public_key_obj = VerifyingKey::from_bytes(&public_key_32)
        .expect("Failed to convert public key bytes to object")
        .to_public_key_der()
        .expect("Failed to convert public key to der format");
    let pub_key_der = public_key_obj.as_bytes();
    let pub_key_buf = PubKeyBuf { 0: pub_key_der.to_vec() };
    let add_user_input = AddUserInput {
        username: "test".to_string(),
        public_keys: vec![pub_key_buf],
    };
    let res = client
        .post("http://localhost:8000/add_user")
        .json(&add_user_input)
        .send();
    let _ = res.unwrap().text().unwrap();
    c.bench_function("lookup_user", |b| b.iter(|| {
        let res = client.get("http://localhost:8000/test/lookup").send();
        let body = res.unwrap().text().unwrap();
        black_box(body);
    }));
}

pub fn bench_add_user(c: &mut Criterion) {
    let client = reqwest::blocking::Client::new();
    let public_key_32: [u8; 32] = [0; 32];
    let public_key_obj = VerifyingKey::from_bytes(&public_key_32)
        .expect("Failed to convert public key bytes to object")
        .to_public_key_der()
        .expect("Failed to convert public key to der format");
    let pub_key_der = public_key_obj.as_bytes();
    let pub_key_buf = PubKeyBuf { 0: pub_key_der.to_vec() };
    let add_user_input = AddUserInput {
        username: "test".to_string(),
        public_keys: vec![pub_key_buf],
    };
    c.bench_function("add_user", |b| b.iter(|| {
        let res = client
            .post("http://localhost:8000/add_user")
            .json(&add_user_input)
            .send();
        let body = res.unwrap().text().unwrap();
        black_box(body);
    }));
}

pub fn bench_user_history(c: &mut Criterion) {
    let history_params_query = HistoryParamsQuery {
        most_recent: 1,
        since_epoch: 0,
    };
    let mut url = Url::parse("http://localhost:8000").unwrap();
    let query_string = serde_qs::to_string(&history_params_query).unwrap();
    url.set_path("/test/history");
    url.set_query(Some(&query_string));

    c.bench_function("user_history", |b| b.iter(|| {
        let client = reqwest::blocking::Client::new();
        let res = client.get("http://localhost:8000/test/history").send();
        let body = res.unwrap().text().unwrap();
        black_box(body);
    }));
}

/* 
pub fn bench_audit_directory(c: &mut Criterion) {
    let client = reqwest::blocking::Client::new();
    let public_key_32_1: [u8; 32] = [0; 32];
    let public_key_obj_1 = VerifyingKey::from_bytes(&public_key_32_1)
        .expect("Failed to convert public key bytes to object")
        .to_public_key_der()
        .expect("Failed to convert public key to der format");
    let pub_key_der_1 = public_key_obj_1.as_bytes();
    let pub_key_buf_1 = PubKeyBuf { 0: pub_key_der_1.to_vec() };
    let add_user_input_1 = AddUserInput {
        username: "test1".to_string(),
        public_keys: vec![pub_key_buf_1],
    };
    let res = client
        .post("http://localhost:8000/add_user")
        .json(&add_user_input_1)
        .send();
    let _ = res.unwrap().text().unwrap();

    let public_key_32_2: [u8; 32] = [1; 32];
    let public_key_obj_2 = VerifyingKey::from_bytes(&public_key_32_2)
        .expect("Failed to convert public key bytes to object")
        .to_public_key_der()
        .expect("Failed to convert public key to der format");
    let pub_key_der_2 = public_key_obj_2.as_bytes();
    let pub_key_buf_2 = PubKeyBuf { 0: pub_key_der_2.to_vec() };
    let add_user_input_2 = AddUserInput {
        username: "test2".to_string(),
        public_keys: vec![pub_key_buf_2],
    };
    let res = client
        .post("http://localhost:8000/add_user")
        .json(&add_user_input_2)
        .send();
    let _ = res.unwrap().text().unwrap();
    c.bench_function("audit_directory", |b| b.iter(|| {
        let client = reqwest::blocking::Client::new();

        let audit_query = AuditQuery { start_epoch: 0, end_epoch: 1 };
        let query_string = serde_qs::to_string(&audit_query).unwrap();
        let mut url = Url::parse("http://localhost:8000").unwrap();
        url.set_path("/audit");
        url.set_query(Some(&query_string));

        let res = client.get(url).send();
        let body = res.unwrap().text().unwrap();
        black_box(body);
    }));
}
*/

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_millis(100));
    targets = bench_get_public_key_request, bench_lookup_user, bench_add_user, bench_user_history, /* bench_audit_directory */
}
criterion_main!(benches);