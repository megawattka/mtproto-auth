use std::cmp::Ordering;

use chrono::Local;

use crate::traits::tl_object::TLObject;


#[derive(Debug)]
pub struct ExternalHeader {
    auth_key_id: [u8; 8],
    last_time: u64,
    offset: i32
} 

impl ExternalHeader {
    pub fn new(auth_key_id: &[u8; 8]) -> Self {
        return Self {
            auth_key_id: *auth_key_id,
            last_time: 0,
            offset: 0
        }
    }
    
    pub fn wrap_packet<T: TLObject>(&mut self, packet: &mut T) -> std::io::Result<Vec<u8>> {
        let msg_id_bytes = self.next_msg_id();
        let packet_bytes = packet.to_bytes();
        let mut concatenated = [
            self.auth_key_id,
            msg_id_bytes.to_le_bytes(),
        ].concat();
        concatenated.extend_from_slice(&(packet_bytes.len() as i32).to_le_bytes());
        concatenated.extend_from_slice(&packet_bytes[..]);
        return Ok(concatenated);
    }

    pub fn next_msg_id(&mut self) -> u64 {
        let now = Local::now().timestamp() as u64;
        
        match now.cmp(&self.last_time) {
            Ordering::Equal => { self.offset += 4; },
            _ => { self.offset = 0; }
        };
        let msg_id = (now * 2_u64.pow(32)) + self.offset as u64;
        self.last_time = now;

        return msg_id;
    }
}