use std::io::BufReader;

use i256::I256;

use crate::traits::tl_object::TLObject;

#[derive(Debug)]
pub struct PQInnerData {
    pub pq: Box<[u8; 8]>,
    pub p: Box<[u8; 4]>,
    pub q: Box<[u8; 4]>,
    pub nonce: i128,
    pub server_nonce: i128,
    pub new_nonce: I256
}

impl TLObject for PQInnerData {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let packet_id = u32::read_from(buffer);
        assert!(packet_id == 0x83c95aec);

        let pq = Box::<[u8; 8]>::read_from(buffer);
        let p = Box::<[u8; 4]>::read_from(buffer);
        let q = Box::<[u8; 4]>::read_from(buffer);
        
        let nonce = i128::read_from(buffer);
        let server_nonce = i128::read_from(buffer);
        let new_nonce = I256::read_from(buffer);

        return PQInnerData {
            pq,
            p,
            q,
            nonce,
            server_nonce,
            new_nonce
        };
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut total: Vec<u8> = Vec::new();

        total.extend_from_slice(&0x83c95aec_u32.to_bytes()); // packet_id
        total.extend_from_slice(&self.pq.to_bytes());
        total.extend_from_slice(&self.p.to_bytes());
        total.extend_from_slice(&self.q.to_bytes());
        
        total.extend_from_slice(&self.nonce.to_bytes()); // nonce
        total.extend_from_slice(&self.server_nonce.to_bytes()); // server_nonce
        total.extend_from_slice(&self.new_nonce.to_bytes()); // new_nonce

        return total;
    }
}