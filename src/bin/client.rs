use std::io::stdin;

use handshake::Handshake;
use tungstenite::{connect, Message};
use url::Url;

const PRESHARED_KEY: [u8; 32] = [
    222, 114, 46, 192, 160, 146, 236, 57, 87, 223, 204, 36, 127, 189, 34, 182,
    136, 147, 168, 126, 49, 22, 89, 195, 205, 10, 131, 203, 42, 150, 223, 225,
];
const AUTHORIZED: &str = "Authorized!";

fn main() {
    let (mut websocket, _) =
        connect(Url::parse("ws://localhost:3012").unwrap())
            .expect("Can't connect");
    let mut handshake = Handshake::new(PRESHARED_KEY);

    websocket
        .write_message(Message::Binary(handshake.public_key()))
        .unwrap();

    if let Message::Binary(pub_key) = websocket.read_message().unwrap() {
        handshake.diffie_hellman(&pub_key);
    } else {
        return;
    }

    websocket
        .write_message(Message::Binary(handshake.auth().unwrap()))
        .unwrap();

    if let Message::Binary(msg) = websocket.read_message().unwrap() {
        if handshake.decrypt_text(msg).unwrap() != AUTHORIZED {
            return;
        }
    } else {
        return;
    }

    loop {
        let mut line = String::new();
        if stdin().read_line(&mut line).is_ok() {
            _ = websocket.write_message(Message::Binary(
                handshake.encrypt_text(&line).unwrap(),
            ));
        }
    }
}
