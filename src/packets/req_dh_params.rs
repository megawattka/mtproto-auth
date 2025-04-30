use std::io::BufReader;

use crate::traits::tl_object::TLObject;

#[derive(Debug)]
pub struct ReqDHParams {
    pub nonce: i128,
    pub server_nonce: i128,
    pub p: Box<[u8; 4]>,
    pub q: Box<[u8; 4]>,
    pub public_key_fingerprint: i64,
    pub encrypted_data: Box<[u8; 256]>
}

impl TLObject for ReqDHParams {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let packet_id = u32::read_from(buffer);
        assert!(packet_id == 0xd712e4be);
        todo!();
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut total: Vec<u8> = Vec::new();

        total.extend_from_slice(&0xd712e4be_u32.to_bytes()); // packet_id

        total.extend_from_slice(&self.nonce.to_bytes());
        total.extend_from_slice(&self.server_nonce.to_bytes()); // server_nonce
        
        total.extend_from_slice(&self.p.to_bytes());
        total.extend_from_slice(&self.q.to_bytes());

        total.extend_from_slice(&self.public_key_fingerprint.to_bytes());
        total.extend_from_slice(&self.encrypted_data.to_bytes());

        return total;
    }
}