use std::{env, io::{Error, ErrorKind}, fs};

use aes::cipher::{
    block_padding::NoPadding,
    BlockDecryptMut as _,
    BlockEncryptMut,
    KeyIvInit
};
use num::{
    bigint::Sign,
    traits::FromBytes,
    BigInt
};
use prime_factorization::Factorization;
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use sha1::{
    Digest,
    Sha1
};


pub fn prime_decompose(num: u64) -> (u32, u32) {
    let mut result = Factorization::run(num);
    result.factors.sort();
    return (result.factors[0] as u32, result.factors[1] as u32);
}

pub fn calculate_padding_bytes(data_len: usize, block_size: usize) -> usize {
    let amount = block_size - (data_len % block_size);
    return if amount == block_size {0} else {amount}
}

pub fn sha1_digest(payload: &[u8]) -> Box<[u8; 20]> {
    let mut object = Sha1::new();
    object.update(payload);
    return Box::<[u8; 20]>::new(object.finalize().try_into().unwrap());
}

pub fn find_cert(values: Vec<i64>) -> std::io::Result<(i64, rsa::RsaPublicKey)> {
    let cwd = env::current_dir().unwrap();
    let keys = cwd.join("keys");
    for num in &values[..] {
        let filename = format!("{num}.pem");
        let pkey = keys.join(filename);
        if pkey.exists() {
            let text = fs::read_to_string(pkey).unwrap();
            return Ok((*num, rsa::RsaPublicKey::from_public_key_pem(&text).unwrap()));
        }
    }
    let err = format!("{:?} public key not found.", values);
    return Err(Error::new(ErrorKind::NotFound, err));
}

pub fn rsa_encrypt(payload: &[u8], m: &rsa::BigUint, e: &rsa::BigUint) -> Box<[u8; 256]> {
    let n = BigInt::from_bytes_be(Sign::Plus, payload);
    let m = BigInt::from_bytes_be(Sign::Plus, &m.to_bytes_be());
    let exp = BigInt::from_bytes_be(Sign::Plus, &e.to_bytes_be());
    let encrypted = n.modpow(&exp, &m);
    return encrypted.to_bytes_be().1.try_into().unwrap();
}

pub fn aes256_ige_decrypt(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 32]
) -> Box<[u8]> {  
    let cipher = ige::Decryptor::<aes::Aes256>::new(key.into(), iv.into());
    let mut buffer = Vec::from(ciphertext);
    cipher
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .unwrap();
    return Box::from(buffer);
}

pub fn aes256_ige_encrypt(
    plaintext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 32]
) -> Box<[u8]> {  
    let cipher = ige::Encryptor::<aes::Aes256>::new(key.into(), iv.into());
    let pt_len = plaintext.len();
    let mut buf = vec![0u8; pt_len];
    buf.copy_from_slice(&plaintext[..]);
    let decrypted = cipher
        .encrypt_padded_mut::<NoPadding>(&mut buf, pt_len)
        .unwrap();
    return Box::from(decrypted);
}

pub fn const_urandom<const N: usize>(rng: &mut rand::rngs::StdRng) -> [u8; N] {
    let mut buffer = vec![0u8; N];
    rng.fill_bytes(&mut buffer);
    return buffer.try_into().unwrap();
}

pub fn xor(c_a: &[u8], c_b: &[u8]) -> Vec<u8> {
    let c_a_num = BigInt::from_be_bytes(c_a);
    let c_b_num = BigInt::from_be_bytes(c_b);
    return (c_a_num ^ c_b_num).to_bytes_be().1;
}