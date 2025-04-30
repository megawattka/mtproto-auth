use std::cmp::Ordering;

use tokio::{io::{AsyncReadExt, AsyncWriteExt, Interest}, net};

use crate::{header::ExternalHeader, traits::tl_object::TLObject};

#[derive(Debug)]
pub struct TcpAbridged {
    stream: net::TcpStream,
    header: ExternalHeader
}

impl TcpAbridged {
    pub async fn new(addr: &str, auth_key_id: &[u8; 8]) -> std::io::Result<TcpAbridged> {
        let mut stream = net::TcpStream::connect(addr).await?;
        let _ = stream.ready(Interest::READABLE | Interest::WRITABLE).await?;
        stream.write_all(&[239]).await?;
        println!("Connected!");
        let header = ExternalHeader::new(auth_key_id);
        return Ok(Self { stream: stream, header: header});
    }
    
    fn prepare_abridged_payload(&self, payload: &Vec<u8>) -> Vec<u8> {
        let size = payload.len() / 4;
        return match size.cmp(&127) {
            Ordering::Less => [&[size as u8], payload.as_slice()].concat(),
            _ => [
                &[127 as u8],
                size.to_le_bytes().chunks(3).next().unwrap(),
                &payload[..]
            ].concat()
        };
    }
    
    pub async fn send_packet<T : TLObject>(&mut self, mut packet: T) -> std::io::Result<usize> {
        let payload = self.header.wrap_packet(&mut packet)?;
        let abridged_payload = self.prepare_abridged_payload(&payload);
        self.stream.write_all(&abridged_payload).await.unwrap();
        return Ok(abridged_payload.len());
    }

    pub async fn read_packet_payload(&mut self) -> std::io::Result<Vec<u8>> {
        let mut size: i32 = self.stream.read_u8().await? as i32;
        if size == 127 {
            let mut additional_size = [0u8; 3];
            self.stream.read(&mut additional_size).await?;
            let size_bytes: [u8; 4] = [
                &additional_size[..],
                &[0u8]
            ].concat().try_into().unwrap();
            size = i32::from_le_bytes(size_bytes);
        };
        let mut buffer: Vec<u8> = vec![0u8; (size * 4) as usize];
        let _ = self.stream.read_exact(&mut buffer).await.unwrap();
        return Ok(buffer);
    }
}