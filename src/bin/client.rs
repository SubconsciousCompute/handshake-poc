use handshake::Handshake;
use tungstenite::{connect, Message};
use url::Url;

const PRESHARED_KEY: [u8; 32] = [
    222, 114, 46, 192, 160, 146, 236, 57, 87, 223, 204, 36, 127, 189, 34, 182,
    136, 147, 168, 126, 49, 22, 89, 195, 205, 10, 131, 203, 42, 150, 223, 225,
];
const AUTHORIZED: &[u8] = "Authorized!".as_bytes();

fn main() {
    let (mut websocket, _) =
        connect(Url::parse("ws://localhost:3012").unwrap())
            .expect("Can't connect");
    let mut handshake = Handshake::new(PRESHARED_KEY);

    websocket
        .write_message(Message::Binary(handshake.public_key()))
        .unwrap();

    if let Message::Binary(pub_key) = websocket.read_message().unwrap() {
        handshake.dh(&pub_key);
    } else {
        return;
    }

    websocket
        .write_message(Message::Binary(handshake.auth().unwrap()))
        .unwrap();

    if let Message::Binary(msg) = websocket.read_message().unwrap() {
        let msg1 = handshake.decypt(msg).unwrap();

        dbg!(&msg1);
        dbg!(&AUTHORIZED);

        if msg1.len() == AUTHORIZED.len()
            && msg1.iter().zip(AUTHORIZED.iter()).all(|(b1, b2)| b1 == b2)
        {
            println!("Authorized!");
        }
    }
}
