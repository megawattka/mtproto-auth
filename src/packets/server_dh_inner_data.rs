use std::io::BufReader;

use crate::traits::tl_object::TLObject;

#[derive(Debug)]
pub struct ServerDHInnerData {
    pub nonce: i128,
    pub server_nonce: i128,
    pub g: i32,
    pub dh_prime: Box<[u8]>,
    pub g_a: Box<[u8]>,
    pub server_time: i32
}

impl TLObject for ServerDHInnerData {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let packet_id = u32::read_from(buffer);
        assert!(packet_id == 0xb5890dba);
        
        let nonce = i128::read_from(buffer);
        let server_nonce = i128::read_from(buffer);
        let g = i32::read_from(buffer);
        let dh_prime = Box::<[u8]>::read_from(buffer);
        let g_a = Box::<[u8]>::read_from(buffer);
        let server_time = i32::read_from(buffer);

        return ServerDHInnerData {
            nonce,
            server_nonce,
            g,
            dh_prime,
            g_a,
            server_time
        };
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut total: Vec<u8> = Vec::new();

        total.extend_from_slice(&0xb5890dba_u32.to_bytes()); // packet_id
        
        total.extend_from_slice(&self.nonce.to_bytes());
        total.extend_from_slice(&self.server_nonce.to_bytes());
        total.extend_from_slice(&self.g.to_bytes());
        total.extend_from_slice(&self.dh_prime.to_bytes());
        total.extend_from_slice(&self.g_a.to_bytes());
        total.extend_from_slice(&self.server_time.to_bytes());

        return total;
    }
}