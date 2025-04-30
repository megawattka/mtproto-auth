use std::io::{BufReader, Read};

use byteorder::{LittleEndian, ReadBytesExt as _};
use i256::I256;

use crate::utils::calculate_padding_bytes;

pub trait TLObject {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self;
    fn to_bytes(&self) -> Vec<u8>;
}

impl TLObject for i32 {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let value = buffer.read_i32::<LittleEndian>().unwrap();
        return value;
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut total = Vec::with_capacity(4);
        total.extend_from_slice(&self.to_le_bytes());
        return total;
    }
}

impl TLObject for u32 {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let value = buffer.read_u32::<LittleEndian>().unwrap();
        return value;
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut total = Vec::with_capacity(4);
        total.extend_from_slice(&self.to_le_bytes());
        return total;
    }
}

impl TLObject for i64 {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let value = buffer.read_i64::<LittleEndian>().unwrap();
        return value;
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut total = Vec::with_capacity(8);
        total.extend_from_slice(&self.to_le_bytes());
        return total;
    }
}

impl TLObject for i128 {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let value = buffer.read_i128::<LittleEndian>().unwrap();
        return value;
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut total = Vec::with_capacity(16);
        total.extend_from_slice(&self.to_le_bytes());
        return total;
    }
}

impl TLObject for I256 {
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let mut buf = vec![0u8; 32];
        buffer.read_exact(&mut buf).unwrap();
        return Self::from_le_bytes(buf[..].try_into().unwrap());
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut total = Vec::with_capacity(32);
        total.extend_from_slice(&self.to_le_bytes());
        return total;
    }
}

impl<T> TLObject for Vec<T>
where
    T: TLObject,
{
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let packet_id = buffer.read_u32::<LittleEndian>().unwrap();
        assert!(packet_id == 0x1cb5c415);
        let size = buffer.read_u32::<LittleEndian>().unwrap();
        let mut total = Vec::with_capacity(size as usize);
        for _ in 0..size {
            total.push(T::read_from(buffer));
        };
        return total;
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut total = Vec::new();
        total.extend_from_slice(&[21, 196, 181, 28]); // Vector packet_id
        total.extend_from_slice(&(self.len() as i32).to_le_bytes());
        for fp in self {
            total.extend_from_slice(&T::to_bytes(&fp));
        }
        return total;
    }
}

impl TLObject for Box<[u8]> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut total = Vec::new();
        let size = self.len();
        if size <= 253 {
            total.push(size as u8);
            total.extend_from_slice(&self[..]);
        } else {
            total.push(254);
            total.extend_from_slice(size.to_le_bytes().chunks(3).next().unwrap());
            total.extend_from_slice(&self[..]);
        }
        let to_extend = calculate_padding_bytes(
            total.len(),
            4
        );
        total.extend_from_slice(&vec![0u8; to_extend]);
        return total;
    }
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let size: usize = buffer.read_u8().unwrap() as usize;
        let mut total: Vec<u8>;
        if size <= 253 {
            total = vec![0u8; size];
        } else {
            let mut additional_size = [0u8; 3];
            buffer.read(&mut additional_size).unwrap();
            let size_bytes: [u8; 4] = [
                &additional_size[..],
                &[0u8]
            ].concat().try_into().unwrap();
            total = vec![0u8; i32::from_le_bytes(size_bytes) as usize];
        }
        buffer.read(&mut total).unwrap();
        let additional = if size == 254 {4} else {1};
        let left = calculate_padding_bytes(
            total.len() + additional,
            4
        );
        buffer.read(&mut vec![0u8; left]).unwrap();
        return total.into_boxed_slice();
    }
}

impl<const N: usize> TLObject for Box<[u8; N]> {
    fn to_bytes(&self) -> Vec<u8> {
        let casted = &self.as_slice()
            .try_into()
            .unwrap();
        return Box::<[u8]>::to_bytes(casted);
    }
    fn read_from(buffer: &mut BufReader<&[u8]>) -> Self {
        let value = Box::<[u8]>::read_from(buffer);
        return value.try_into().unwrap();
    }
}