use aes::{
    cipher::{BlockDecrypt, BlockEncrypt},
    Aes256, Block,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{ecdh::EphemeralSecret, PublicKey};
use rand_core::OsRng;
use sha2::Sha256;

const BLOCK_SIZE: usize = 16;

pub struct Handshake {
    pre_shared_key: [u8; 32],
    private_key: EphemeralSecret,
    pub cipher: Option<Aes256>,
    auth_msg: Option<Vec<u8>>,
}

impl Handshake {
    pub fn new(pre_shared_key: [u8; 32]) -> Self {
        Self {
            pre_shared_key,
            private_key: EphemeralSecret::random(&mut OsRng),
            cipher: None,
            auth_msg: None,
        }
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.private_key.public_key().to_sec1_bytes().to_vec()
    }

    pub fn dh(&mut self, pub_key: &[u8]) {
        let shared_secret = self
            .private_key
            .diffie_hellman(&PublicKey::from_sec1_bytes(pub_key).unwrap());

        let h = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());

        let mut enc_key = [0; 32];
        let mut chan_bind_token = [0; 32];

        assert!(h.expand(&[0; 32], &mut enc_key).is_ok());
        assert!(h.expand(&[1; 32], &mut chan_bind_token).is_ok());

        self.cipher = Some({
            use aes::cipher::KeyInit;
            Aes256::new_from_slice(&enc_key).unwrap()
        });

        self.auth_msg = Some(
            Hmac::<Sha256>::new_from_slice(&chan_bind_token)
                .unwrap()
                .chain_update(self.pre_shared_key)
                .finalize()
                .into_bytes()
                .to_vec(),
        );
    }

    pub fn auth(&self) -> Result<Vec<u8>, ()> {
        self.encrypt(self.auth_msg.as_ref().ok_or(())?.clone())
    }

    pub fn verify(&self, encrypted: Vec<u8>) -> Result<bool, ()> {
        Ok(*self.auth_msg.as_ref().ok_or(())? == self.decypt(encrypted)?)
    }

    fn encrypt(&self, bytes: Vec<u8>) -> Result<Vec<u8>, ()> {
        let cipher = self.cipher.as_ref().ok_or(())?;
        let mut encrypted = bytes;

        for chunk in encrypted.chunks_mut(BLOCK_SIZE) {
            cipher.encrypt_block(Block::from_mut_slice(chunk));
        }

        Ok(encrypted)
    }

    pub fn encrypt_text(&self, text: &str) -> Result<Vec<u8>, ()> {
        let mut text_bytes = text.as_bytes().to_vec();
        let orig_len = text_bytes.len();
        text_bytes.resize(orig_len + BLOCK_SIZE - (orig_len % BLOCK_SIZE), 32);

        self.encrypt(text_bytes)
    }

    pub fn decypt(&self, bytes: Vec<u8>) -> Result<Vec<u8>, ()> {
        let cipher = self.cipher.as_ref().ok_or(())?;
        let mut decrypted = bytes;

        let orig_len = decrypted.len();
        decrypted.resize(orig_len + BLOCK_SIZE - (orig_len % BLOCK_SIZE), 0);

        for chunk in decrypted.chunks_mut(BLOCK_SIZE) {
            cipher.decrypt_block(Block::from_mut_slice(chunk));
        }

        decrypted.resize(orig_len, 0);

        Ok(decrypted)
    }
}

// #[cfg(test)]
// mod tests {
//   use aes::{
//     cipher::{BlockDecrypt, BlockEncrypt},
//     Aes256, Block,
//   };
//   use hkdf::Hkdf;
//   use hmac::{Hmac, Mac};
//   use p256::ecdh::EphemeralSecret;
//   use rand::{thread_rng, Rng};
//   use rand_core::OsRng;
//   use sha2::Sha256;

//   #[test]
//   fn handshake() {
//     let pre_shared_key: [u8; 32] = thread_rng().gen();

//     let a_priv_key = EphemeralSecret::random(&mut OsRng);
//     let a_pub_key = a_priv_key.public_key();

//     let b_priv_key = EphemeralSecret::random(&mut OsRng);
//     let b_pub_key = b_priv_key.public_key();

//     let a_shared_secret = a_priv_key.diffie_hellman(&b_pub_key);
//     let b_shared_secret = b_priv_key.diffie_hellman(&a_pub_key);

//     assert_eq!(
//       a_shared_secret.raw_secret_bytes(),
//       b_shared_secret.raw_secret_bytes()
//     );

//     let h = Hkdf::<Sha256>::new(None, a_shared_secret.raw_secret_bytes());

//     let mut enc_key = [0u8; 32];
//     let mut chan_bind_token = [0u8; 32];

//     assert!(h.expand(&[0; 32], &mut enc_key).is_ok());
//     assert!(h.expand(&[1; 32], &mut chan_bind_token).is_ok());

//     let auth_msg = Hmac::<Sha256>::new_from_slice(&chan_bind_token)
//       .unwrap()
//       .chain_update(pre_shared_key)
//       .finalize()
//       .into_bytes();

//     let mut encrypted = auth_msg;

//     let cipher = {
//       use aes::cipher::KeyInit;
//       Aes256::new_from_slice(&enc_key).unwrap()
//     };

//     for chunk in encrypted.chunks_mut(16) {
//       cipher.encrypt_block(Block::from_mut_slice(chunk))
//     }

//     let mut decrypted = encrypted;

//     for chunk in decrypted.chunks_mut(16) {
//       cipher.decrypt_block(Block::from_mut_slice(chunk))
//     }

//     assert_eq!(auth_msg, decrypted);
//   }
// }
