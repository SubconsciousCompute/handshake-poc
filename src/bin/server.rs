use std::{net::TcpListener, thread::spawn};

use handshake::Handshake;
use tungstenite::{accept, Message};

const PRESHARED_KEY: [u8; 32] = [
    222, 114, 46, 192, 160, 146, 236, 57, 87, 223, 204, 36, 127, 189, 34, 182,
    136, 147, 168, 126, 49, 22, 89, 195, 205, 10, 131, 203, 42, 150, 223, 225,
];
const AUTHORIZED: &str = "Authorized!";

fn main() {
    for stream in TcpListener::bind("127.0.0.1:3012")
        .unwrap()
        .incoming()
        .flatten()
    {
        spawn(move || {
            println!("Connection Received: {}", stream.peer_addr().unwrap());

            let mut websocket = accept(stream).unwrap();
            let mut handshake = Handshake::new(PRESHARED_KEY);

            if let Message::Binary(pub_key) = websocket.read_message().unwrap()
            {
                handshake.diffie_hellman(&pub_key);
            } else {
                return;
            }

            websocket
                .write_message(Message::Binary(handshake.public_key()))
                .unwrap();

            if let Message::Binary(auth) = websocket.read_message().unwrap() {
                if handshake.verify(auth).is_err() {
                    return;
                }
            } else {
                return;
            }

            websocket
                .write_message(Message::Binary(
                    handshake.encrypt_text(AUTHORIZED).unwrap(),
                ))
                .unwrap();

            loop {
                if let Ok(Message::Binary(msg)) = websocket.read_message() {
                    println!("{}", &handshake.decrypt_text(msg).unwrap());
                }
            }
        });
    }
}
