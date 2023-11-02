#![no_std]

pub struct Payload {
    pub buff: [u8; 128],
    pub len: usize
}