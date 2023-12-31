use std::{
    io::{
        self,
        prelude::{Read, Write},
    },
    net::{TcpListener, TcpStream},
    thread::spawn,
};

use aes::{cipher::BlockDecrypt, Block};
use handshake::{Handshake, HandshakeError};
use log::{error, info};
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

const SERVER_ADDR: &str = "127.0.0.1:3000";

fn runner(mut stream: TcpStream) -> Result<(), StreamError> {
    let peer_addr = stream
        .peer_addr()
        .map_or("Peer".to_string(), |a| a.to_string());

    info!("Connection Received: {peer_addr}");

    let mut handshake = Handshake::new(&SIGNING_KEY)?;

    stream.write_all(&handshake.send())?;

    let mut pub_key = [0; 129];
    stream.read_exact(&mut pub_key)?;

    let cipher = handshake.receive(&pub_key)?;

    info!("{peer_addr}: Handshake Complete!");

    loop {
        let mut buf = [0; BLOCK_SIZE];
        stream.read_exact(&mut buf)?;
        cipher.decrypt_block(Block::from_mut_slice(&mut buf));

        println!("{peer_addr}: {}", String::from_utf8_lossy(&buf).trim());
    }
}

fn main() {
    env_logger::init();

    match TcpListener::bind(SERVER_ADDR) {
        Ok(listener) => {
            for stream in listener.incoming().flatten() {
                spawn(|| {
                    if let Err(err) = runner(stream) {
                        error!("Stream Error: {err}");
                    }
                });
            }
        }
        Err(err) => error!("Error binding to {SERVER_ADDR}: {err}"),
    }
}
