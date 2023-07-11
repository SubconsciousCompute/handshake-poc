use aes::Aes256;
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret,
    ecdsa::{
        self,
        signature::{Signer, Verifier},
        Signature, SigningKey,
    },
    elliptic_curve, PublicKey,
};
use rand_core::OsRng;
use sha2::Sha256;
use thiserror::Error;

pub struct Handshake {
    signing_key: SigningKey,
    private_key: EphemeralSecret,
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("Wrong Public Key Length")]
    WrongPublicKeyLength,

    #[error(transparent)]
    InvalidSignature(#[from] ecdsa::Error),

    #[error(transparent)]
    InvalidPublicKey(#[from] elliptic_curve::Error),
}

impl Handshake {
    pub fn new(signing_key: &[u8]) -> Self {
        Self {
            signing_key: SigningKey::from_slice(signing_key).unwrap(),
            private_key: EphemeralSecret::random(&mut OsRng),
        }
    }

    pub fn public_key(&self) -> [u8; 129] {
        let mut pk = [0u8; 129];
        pk[..65]
            .copy_from_slice(&self.private_key.public_key().to_sec1_bytes());

        let signature: Signature = self.signing_key.sign(&pk[..65]);
        pk[65..].copy_from_slice(&signature.to_bytes());

        pk
    }

    pub fn handshake(
        &mut self,
        pub_key: &[u8],
    ) -> Result<Aes256, HandshakeError> {
        if pub_key.len() != 129 {
            return Err(HandshakeError::WrongPublicKeyLength);
        }

        self.signing_key.verifying_key().verify(
            &pub_key[..65],
            &Signature::from_slice(&pub_key[65..]).unwrap(),
        )?;

        let shared_secret = self
            .private_key
            .diffie_hellman(&PublicKey::from_sec1_bytes(&pub_key[..65])?);
        let h = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());

        let mut enc_key = [0; 32];
        h.expand(&[0; 32], &mut enc_key).unwrap();

        Ok({
            use aes::cipher::KeyInit;
            Aes256::new_from_slice(&enc_key).unwrap()
        })
    }
}
