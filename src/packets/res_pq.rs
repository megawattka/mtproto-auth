use std::io::BufReader;

use crate::traits::tl_object::TLObject;

#[derive(Debug)]
pub struct ResPQ {
    pub nonce: i128,
    pub server_nonce: i128,
    pub pq: Box<[u8; 8]>,
    pub server_public_key_fingerprints: Vec<i64>
}

impl TLObject for ResPQ {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let packet_id = u32::read_from(buffer);
        assert!(packet_id == 0x05162463);
        
        let nonce = i128::read_from(buffer);
        let server_nonce = i128::read_from(buffer);
        
        let pq = Box::<[u8; 8]>::read_from(buffer);
        let server_public_key_fingerprints = Vec::<i64>::read_from(buffer);

        return ResPQ {
            nonce,
            server_nonce,
            pq,
            server_public_key_fingerprints
        };
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut total: Vec<u8> = Vec::new();
        
        total.extend_from_slice(&0x05162463_u32.to_bytes());
        total.extend_from_slice(&self.nonce.to_bytes());
        total.extend_from_slice(&self.server_nonce.to_bytes());
        
        total.extend_from_slice(&self.pq.to_bytes());

        total.extend_from_slice(&self.server_public_key_fingerprints.to_bytes());

        return total;
    }
}