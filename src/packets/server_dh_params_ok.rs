use std::io::BufReader;

use crate::traits::tl_object::TLObject;

#[derive(Debug)]
pub struct ServerDHParamsOK {
    pub nonce: i128,
    pub server_nonce: i128,
    pub encrypted_answer: Box<[u8]>
}

impl TLObject for ServerDHParamsOK {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let packet_id = u32::read_from(buffer);
        assert!(packet_id == 0xd0e8075c);
        
        let nonce = i128::read_from(buffer);
        let server_nonce = i128::read_from(buffer);
        let encrypted_answer = Box::<[u8]>::read_from(buffer);

        return ServerDHParamsOK {
            nonce,
            server_nonce,
            encrypted_answer
        };
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut total: Vec<u8> = Vec::new();

        total.extend_from_slice(&0xd0e8075c_u32.to_bytes()); // packet_id
        
        total.extend_from_slice(&self.nonce.to_bytes());
        total.extend_from_slice(&self.server_nonce.to_bytes());
        total.extend_from_slice(&self.encrypted_answer.to_bytes());

        return total;
    }
}