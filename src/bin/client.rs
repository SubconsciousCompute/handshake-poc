use std::io::{self, prelude::*, stdin};
use std::net::TcpStream;

use aes::{cipher::BlockEncrypt, Block};
use handshake::{Handshake, HandshakeError};
use thiserror::Error;

const BLOCK_SIZE: usize = 16;

const SIGNING_KEY: [u8; 32] = [
    113, 42, 194, 252, 108, 15, 145, 212, 169, 60, 154, 2, 4, 113, 212, 245,
    97, 91, 65, 222, 175, 245, 186, 75, 213, 245, 190, 165, 180, 44, 188, 120,
];

#[derive(Debug, Error)]
enum StreamError {
    #[error(transparent)]
    IOError(#[from] io::Error),

    #[error(transparent)]
    HandShakeError(#[from] HandshakeError),
}

fn main() -> Result<(), StreamError> {
    let mut stream = TcpStream::connect("127.0.0.1:3000").unwrap();
    println!("Connection Established: {}", stream.peer_addr().unwrap());

    let mut handshake = Handshake::new(&SIGNING_KEY);

    stream.write_all(&handshake.public_key())?;

    let mut pub_key = [0; 129];
    stream.read_exact(&mut pub_key)?;

    let cipher = handshake.handshake(&pub_key)?;

    println!("Key Exchange Complete!");

    loop {
        let mut buf = [32; BLOCK_SIZE];
        _ = stdin().read(&mut buf)?;
        cipher.encrypt_block(Block::from_mut_slice(&mut buf));

        stream.write_all(&buf)?;
    }
}
