use std::io::BufReader;

use crate::traits::tl_object::TLObject;

#[derive(Debug)]
pub struct DHGenOk {
    pub nonce: i128,
    pub server_nonce: i128,
    pub new_nonce_hash1: i128
}

impl TLObject for DHGenOk {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let packet_id = u32::read_from(buffer);
        assert!(packet_id == 0x3bcbf734);
        
        let nonce = i128::read_from(buffer);
        let server_nonce = i128::read_from(buffer);
        let new_nonce_hash1 = i128::read_from(buffer);

        return DHGenOk {
            nonce,
            server_nonce,
            new_nonce_hash1
        };
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut total: Vec<u8> = Vec::new();

        total.extend_from_slice(&0x3bcbf734_u32.to_bytes()); // packet_id
        
        total.extend_from_slice(&self.nonce.to_bytes());
        total.extend_from_slice(&self.server_nonce.to_bytes());
        total.extend_from_slice(&self.new_nonce_hash1.to_bytes());

        return total;
    }
}