use std::io::BufReader;

use crate::traits::tl_object::TLObject;

#[derive(Debug)]
pub struct ReqPQMulti {
    pub nonce: i128
}

impl TLObject for ReqPQMulti {    
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let packet_id = u32::read_from(buffer);
        assert!(packet_id == 0xbe7e8ef1);
        
        let nonce = i128::read_from(buffer);
        
        return ReqPQMulti { nonce };
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut total: Vec<u8> = Vec::new();
        
        total.extend_from_slice(&0xbe7e8ef1_u32.to_bytes()); // packet_id
        total.extend_from_slice(&self.nonce.to_bytes()); // nonce

        return total;
    }
}