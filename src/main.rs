use std::{io::BufReader, time::Instant};

use base64::{prelude::BASE64_STANDARD, Engine};
use bytes::Bytes;
use i256::i256;
use num::{traits::FromBytes, BigUint, FromPrimitive, One};
use rsa::traits::PublicKeyParts;
use traits::tl_object::TLObject;
use rand::{self, Rng, RngCore, SeedableRng};

use packets::{
    client_dh_inner_data::ClientDHInnerData,
    dh_gen_ok::DHGenOk,
    p_q_inner_data::PQInnerData,
    req_dh_params::ReqDHParams,
    req_pq_multi::ReqPQMulti,
    res_pq::ResPQ,
    server_dh_inner_data::ServerDHInnerData,
    server_dh_params_ok::ServerDHParamsOK,
    set_client_dh_params::SetClientDHParams
};
use utils::{
    aes256_ige_decrypt,
    aes256_ige_encrypt,
    calculate_padding_bytes,
    find_cert,
    prime_decompose,
    rsa_encrypt,
    sha1_digest,
    const_urandom,
    xor
};

mod header;
mod network;
mod utils;
mod packets;
mod traits;

const CURRENT_DH_PRIME_BYTES: [u8; 256] = [199, 28, 174, 185, 198, 177, 201, 4, 142, 108, 82, 47, 112, 241, 63, 115, 152, 13, 64, 35, 142, 62, 33, 193, 73, 52, 208, 55, 86, 61, 147, 15, 72, 25, 138, 10, 167, 193, 64, 88, 34, 148, 147, 210, 37, 48, 244, 219, 250, 51, 111, 110, 10, 201, 37, 19, 149, 67, 174, 212, 76, 206, 124, 55, 32, 253, 81, 246, 148, 88, 112, 90, 198, 140, 212, 254, 107, 107, 19, 171, 220, 151, 70, 81, 41, 105, 50, 132, 84, 241, 143, 175, 140, 89, 95, 100, 36, 119, 254, 150, 187, 42, 148, 29, 91, 205, 29, 74, 200, 204, 73, 136, 7, 8, 250, 155, 55, 142, 60, 79, 58, 144, 96, 190, 230, 124, 249, 164, 164, 166, 149, 129, 16, 81, 144, 126, 22, 39, 83, 181, 107, 15, 107, 65, 13, 186, 116, 216, 168, 75, 42, 20, 179, 20, 78, 14, 241, 40, 71, 84, 253, 23, 237, 149, 13, 89, 101, 180, 185, 221, 70, 88, 45, 177, 23, 141, 22, 156, 107, 196, 101, 176, 214, 255, 156, 163, 146, 143, 239, 91, 154, 228, 228, 24, 252, 21, 232, 62, 190, 160, 248, 127, 169, 255, 94, 237, 112, 5, 13, 237, 40, 73, 244, 123, 249, 89, 217, 86, 133, 12, 233, 41, 133, 31, 13, 129, 21, 246, 53, 177, 5, 238, 46, 78, 21, 208, 75, 36, 84, 191, 111, 79, 173, 240, 52, 177, 4, 3, 17, 156, 216, 227, 185, 47, 204, 91];

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let started = Instant::now();
    let mut transport = network::TcpAbridged::new("149.154.167.51:443", &[0; 8]).await?;
    let mut rng = rand::rngs::StdRng::from_os_rng();
    let nonce: i128 = rng.random();
    dbg!(nonce);

    let req_pq_multi = ReqPQMulti { nonce };

    transport.send_packet(req_pq_multi).await?;
    let res_pq_response= transport.read_packet_payload().await?;

    let mut res_pq_reader = BufReader::new(&res_pq_response[20..]);
    let res_pq = ResPQ::read_from(&mut res_pq_reader);

    let server_nonce = res_pq.server_nonce;
    dbg!(server_nonce);

    let pq = res_pq.pq;
    let pq_num: u64 = u64::from_be_bytes(*pq);
    println!("Starting prime decomposition for {}", pq_num);
    let ts = Instant::now();
    let (p, q) = prime_decompose(pq_num);
    println!("Done prime decomposition in {:.2?}ms p={p} q={q}", ts.elapsed());
    let (fp, pkey) = find_cert(res_pq.server_public_key_fingerprints).unwrap();
    println!("using RSA key: {}.pem", fp);

    let nonce_bytes: [u8; 32] = const_urandom(&mut rng);
    let new_nonce = i256::from_be_bytes(nonce_bytes);
    dbg!(new_nonce);

    let pq_inner_data_obj = PQInnerData {
        pq,
        p: Box::new(p.to_be_bytes()),
        q: Box::new(q.to_be_bytes()),
        nonce,
        server_nonce,
        new_nonce
    };
    let pq_inner_data = pq_inner_data_obj.to_bytes();

    let mut pq_digest = sha1_digest(&pq_inner_data).to_vec();
    let padding_len = 255 - (pq_inner_data.len() + pq_digest.len());

    let mut padding = vec![0u8; padding_len];
    rng.fill_bytes(&mut padding);

    pq_digest.extend_from_slice(&pq_inner_data);
    pq_digest.extend_from_slice(&padding);
    let encrypted_data: Box<[u8; 256]> = rsa_encrypt(&pq_digest, pkey.n(), pkey.e());

    let req_dh_params = ReqDHParams {
        nonce,
        server_nonce,
        encrypted_data,
        p: Box::new(p.to_be_bytes()),
        q: Box::new(q.to_be_bytes()),
        public_key_fingerprint: fp
    };

    transport.send_packet(req_dh_params).await?;
    let dh_response = transport.read_packet_payload().await?;
    let mut dh_reader = BufReader::new(&dh_response[20..]);

    let server_dh_params_ok = ServerDHParamsOK::read_from(&mut dh_reader);
    let encrypted_answer = server_dh_params_ok.encrypted_answer;

    let new_nonce_le = &new_nonce.to_le_bytes()[..];
    let server_nonce_le = &server_nonce.to_le_bytes()[..];

    let tmp_aes_key: &[u8; 32] = &[
        &sha1_digest(&[new_nonce_le, server_nonce_le].concat()),
        &sha1_digest(&[server_nonce_le, new_nonce_le].concat())[..12]
    ].concat().try_into().unwrap();

    let tmp_aes_iv: &[u8; 32] = &[
        &sha1_digest(&[server_nonce_le, new_nonce_le].concat())[12..],
        &sha1_digest(&[new_nonce_le, new_nonce_le].concat()),
        &new_nonce_le[..4]
    ].concat().try_into().unwrap();

    let server_dh_inner_decrypted = aes256_ige_decrypt(&*encrypted_answer, &tmp_aes_key, &tmp_aes_iv);
    let mut server_dh_inner_reader = BufReader::new(&server_dh_inner_decrypted[20..]);

    let server_dh_inner = ServerDHInnerData::read_from(&mut server_dh_inner_reader);
    let dh_prime = BigUint::from_be_bytes(&*server_dh_inner.dh_prime);
    let timedelta = server_dh_inner.server_time as i64 - chrono::Local::now().timestamp();
    dbg!(timedelta);

    let g = server_dh_inner.g;
    let b_bytes: [u8; 256] = const_urandom(&mut rng);
    let b = BigUint::from_be_bytes(&b_bytes);

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
    let dh_inner_bytes = client_dh_inner.to_bytes();
    let dh_inner_digest = sha1_digest(&dh_inner_bytes);
    let dh_inner_padding_len = calculate_padding_bytes(
        dh_inner_bytes.len() + dh_inner_digest.len(),
        16
    );
    let mut dh_padding = vec![0u8; dh_inner_padding_len];
    rng.fill_bytes(&mut dh_padding);
    
    let dh_data_with_hash = &[
        &dh_inner_digest,
        &dh_inner_bytes[..],
        &dh_padding
    ].concat()[..];

    let encrypted_dh = aes256_ige_encrypt(dh_data_with_hash, tmp_aes_key, tmp_aes_iv);
    let set_dh_params = SetClientDHParams {
        nonce,
        server_nonce,
        encrypted_data: Box::from(encrypted_dh)
    };

    transport.send_packet(set_dh_params).await?;
    let dh_gen_ok_response = transport.read_packet_payload().await?;
    let mut dh_gen_ok_reader = BufReader::new(&dh_gen_ok_response[20..]);
    let dh_gen_ok_obj = DHGenOk::read_from(&mut dh_gen_ok_reader);

    let g_a = BigUint::from_bytes_be(&server_dh_inner.g_a);
    let auth_key = &g_a.modpow(&b, &dh_prime).to_bytes_be()[..];
    let auth_key_digest = &sha1_digest(auth_key)[..];
    println!("Auth key generated successfully! sha1: {}", hex::encode(auth_key_digest));

    println!("Performing security checks...");
    let current_dh_prime = BigUint::from_bytes_be(&CURRENT_DH_PRIME_BYTES);
    assert_eq!(dh_prime, current_dh_prime);

    let g_b_num = BigUint::from_bytes_be(&g_b);
    let substracted = &dh_prime - BigUint::one();
    assert!(1 < g && BigUint::from_i32(g).unwrap() < substracted);
    assert!(1 < g && g_a < substracted);
    assert!(1 < g && g_b_num < substracted);

    let two_power_of_2k = BigUint::one() << (2048 - 64);
    assert!(two_power_of_2k < g_a  && g_a < &dh_prime - &two_power_of_2k);
    assert!(two_power_of_2k < g_b_num  && g_b_num < dh_prime - two_power_of_2k);

    let dh_inner_serialized = server_dh_inner.to_bytes();
    assert_eq!(server_dh_inner_decrypted[..20], sha1_digest(&dh_inner_serialized));

    assert_eq!(nonce, res_pq.nonce);
    assert_eq!(nonce, server_dh_params_ok.nonce);
    assert_eq!(nonce, dh_gen_ok_obj.nonce);
    assert_eq!(server_nonce, server_dh_params_ok.server_nonce);

    let raw_server_salt = xor(&new_nonce_le[..8], &server_nonce_le[..8]);
    let server_salt = Bytes::from(raw_server_salt);
    dbg!(server_salt);
    println!("Done in {:.2?}ms", started.elapsed());

    let auth_key_base64 = BASE64_STANDARD.encode(auth_key);
    dbg!(auth_key_base64);

    return Ok(());

}
