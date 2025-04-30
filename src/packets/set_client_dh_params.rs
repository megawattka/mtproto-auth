use std::io::BufReader;

use crate::traits::tl_object::TLObject;

#[derive(Debug)]
pub struct SetClientDHParams {
    pub nonce: i128,
    pub server_nonce: i128,
    pub encrypted_data: Box<[u8]>
}

impl TLObject for SetClientDHParams {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let packet_id = u32::read_from(buffer);
        assert!(packet_id == 0xf5045f1f);
        
        let nonce = i128::read_from(buffer);
        let server_nonce = i128::read_from(buffer);
        let encrypted_data = Box::<[u8]>::read_from(buffer);

        return SetClientDHParams {
            nonce,
            server_nonce,
            encrypted_data
        };
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut total: Vec<u8> = Vec::new();

        total.extend_from_slice(&0xf5045f1f_u32.to_bytes()); // packet_id
        
        total.extend_from_slice(&self.nonce.to_bytes());
        total.extend_from_slice(&self.server_nonce.to_bytes());
        total.extend_from_slice(&self.encrypted_data.to_bytes());

        return total;
    }
}