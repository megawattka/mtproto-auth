use std::{array::from_fn, io::{BufReader, Read}};

use i256::i256;
use ::i256::{u256, I256};
use num::{traits::FromBytes, BigInt, BigUint};
use rsa::traits::PublicKeyParts;
use chrono::Local;
use traits::tl_object::TLObject;
use rand::{self, Rng, RngCore, SeedableRng};
use packets::{
    client_dh_inner_data::{self, ClientDHInnerData}, p_q_inner_data::PQInnerData, req_dh_params::ReqDHParams, req_pq_multi::ReqPQMulti, res_pq::ResPQ, server_dh_inner_data::ServerDHInnerData, server_dh_params_ok::ServerDHParamsOK
};
use utils::{aes256_ige_decrypt, find_cert, prime_decompose, rsa_encrypt, sha1_digest, urandom};

mod header;
mod network;
mod utils;
mod packets;
mod traits;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut transport = network::TcpAbridged::new("149.154.167.51:443", &[0; 8]).await?;
    let mut rng = rand::rngs::StdRng::from_os_rng();
    let nonce: i128 = rng.random();
    println!("nonce={}", nonce);
    
    let req_pq_multi = ReqPQMulti { nonce };
    
    let _ = transport.send_packet(req_pq_multi).await?;
    let res_pq_response= transport.read_packet_payload().await?;

    let mut res_pq_reader = BufReader::new(&res_pq_response[20..]);
    let res_pq = ResPQ::read_from(&mut res_pq_reader);
    let server_nonce = res_pq.server_nonce;
    // println!("Constructed packet ResPQ: {:?}", res_pq);

    let pq = res_pq.pq;
    let pq_num: u64 = u64::from_be_bytes(*pq);
    // println!("got pq num: {}", pq_num);
    println!("Starting prime decomposition.");
    let ts = Local::now().timestamp_millis();
    let (p, q) = prime_decompose(pq_num);
    println!("Done prime decomposition in {} p={p} q={q}", Local::now().timestamp_millis() - ts);
    let (fp, pkey) = find_cert(res_pq.server_public_key_fingerprints).unwrap();
    println!("using RSA key: {}.pem", fp);
    
    let nonce_bytes: [u8; 32] = urandom(&mut rng);
    let new_nonce = i256::from_be_bytes(nonce_bytes);
    println!("generated new_nonce: {}", new_nonce);
    
    let server_nonce = res_pq.server_nonce;
    // println!("server_nonce: {}", server_nonce);
    let pq_inner_data_obj = PQInnerData {
        pq,
        p: Box::new(p.to_be_bytes()),
        q: Box::new(q.to_be_bytes()),
        nonce,
        server_nonce,
        new_nonce
    };
    // println!("Constructed pq_inner_data: {:?}", pq_inner_data_obj);
    let pq_inner_data = pq_inner_data_obj.to_bytes();

    let mut pq_digest = sha1_digest(&pq_inner_data).to_vec();
    // println!("pq_digest: {:?}", pq_digest);
    let padding_len = 255 - (pq_inner_data.len() + pq_digest.len());
    // println!("using padding len: {}", padding_len);
    
    let mut padding = vec![0u8; padding_len];
    rng.fill_bytes(&mut padding);
    // println!("random padding bytes: {:?}", padding);
    
    pq_digest.extend_from_slice(&pq_inner_data);
    pq_digest.extend_from_slice(&padding);
    // println!("total value with sha: {:?}", pq_digest);

    let encrypted_data: Box<[u8; 256]> = rsa_encrypt(&pq_digest, pkey.n(), pkey.e());
    // println!("being encrypted into: {:?}", encrypted_data);
    // println!("nonce={}, server_nonce={}", nonce, server_nonce);

    let req_dh_params = ReqDHParams {
        nonce,
        server_nonce,
        encrypted_data,
        p: Box::new(p.to_be_bytes()),
        q: Box::new(q.to_be_bytes()),
        public_key_fingerprint: fp
    };
    // println!("constructed REQ_DH_PARAMS: {:?}", req_dh_params);

    transport.send_packet(req_dh_params).await?;
    let dh_response = transport.read_packet_payload().await?;
    let mut dh_reader = BufReader::new(&dh_response[20..]);

    let server_dh_params_ok = ServerDHParamsOK::read_from(&mut dh_reader);
    let encrypted_answer = server_dh_params_ok.encrypted_answer;

    let new_nonce_le = &new_nonce.to_le_bytes()[..];
    let server_nonce_le = &server_nonce.to_le_bytes()[..];
    
    let tmp_aes_key: &[u8; 32] = &[
        &*sha1_digest(&[new_nonce_le, server_nonce_le].concat()),
        &sha1_digest(&[server_nonce_le, new_nonce_le].concat())[..12]
    ].concat().try_into().unwrap();
    // println!("{:?} {:?} {}", tmp_aes_key, new_nonce, server_nonce);

    let tmp_aes_iv: &[u8; 32] = &[
        &sha1_digest(&[server_nonce_le, new_nonce_le].concat())[12..],
        &*sha1_digest(&[new_nonce_le, new_nonce_le].concat()),
        &new_nonce_le[..4]
    ].concat().try_into().unwrap();

    let server_dh_inner_decrypted = aes256_ige_decrypt(&*encrypted_answer, &tmp_aes_key, &tmp_aes_iv);
    let mut server_dh_inner_reader = BufReader::new(&server_dh_inner_decrypted[20..]);
    // println!("{:?}", server_dh_inner_reader);

    let server_dh_inner = ServerDHInnerData::read_from(&mut server_dh_inner_reader);
    let dh_prime = BigUint::from_be_bytes(&*server_dh_inner.dh_prime);
    let delta_time = server_dh_inner.server_time as i64 - chrono::Local::now().timestamp();
    println!("delta_time={}", delta_time);

    let g = server_dh_inner.g;
    let b_bytes: [u8; 256] = urandom(&mut rng);
    let b = BigUint::from_be_bytes(&b_bytes);
    println!("{} {} {}", g, b, dh_prime);
    let g_b: [u8; 256] = BigUint::from(g as u32)
        .modpow(&b, &dh_prime)
        .to_bytes_be()
        .try_into()
        .unwrap();

    let retry_id: i64 = 0;
    let client_dh_inner = ClientDHInnerData {
        nonce,
        server_nonce,
        retry_id,
        g_b: Box::new(g_b)
    };
    println!("{:?}", client_dh_inner);
    println!("{:?}", client_dh_inner.to_bytes());

    return Ok(());
}
