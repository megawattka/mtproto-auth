use std::io::BufReader;

use crate::traits::tl_object::TLObject;

#[derive(Debug)]
pub struct ClientDHInnerData {
    pub nonce: i128,
    pub server_nonce: i128,
    pub retry_id: i64,
    pub g_b: Box<[u8; 256]>
}

impl TLObject for ClientDHInnerData {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let packet_id = u32::read_from(buffer);
        assert!(packet_id == 0x6643b654);
        
        let nonce = i128::read_from(buffer);
        let server_nonce = i128::read_from(buffer);
        let retry_id = i64::read_from(buffer);
        let g_b = Box::<[u8; 256]>::read_from(buffer);

        return ClientDHInnerData {
            nonce,
            server_nonce,
            retry_id,
            g_b
        };
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut total: Vec<u8> = Vec::new();

        total.extend_from_slice(&0x6643b654_u32.to_bytes()); // packet_id
        
        total.extend_from_slice(&self.nonce.to_bytes());
        total.extend_from_slice(&self.server_nonce.to_bytes());
        
        total.extend_from_slice(&self.retry_id.to_bytes());
        total.extend_from_slice(&self.g_b.to_bytes());

        return total;
    }
}