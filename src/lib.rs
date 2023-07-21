use aes::{cipher, Aes256};
use hkdf::{self, Hkdf};
use log::debug;
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
    #[error("Invalid length for Public Key")]
    PubKeyLengthInvalidLength,

    #[error(transparent)]
    InvalidKey(#[from] ecdsa::Error),

    #[error(transparent)]
    AesKeyInvalidLength(#[from] cipher::InvalidLength),

    #[error("Invalid length for HKDF Key")]
    HkdfKeyInvalidLength,

    #[error(transparent)]
    InvalidPublicKey(#[from] elliptic_curve::Error),
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Handshake {
    pub fn new(signing_key: &[u8]) -> Result<Self, HandshakeError> {
        debug!("Handshake Started!");
        debug!("Signing Key: {}", to_hex(signing_key));

        Ok(Self {
            signing_key: SigningKey::from_slice(signing_key)?,
            private_key: EphemeralSecret::random(&mut OsRng),
        })
    }

    pub fn send(&self) -> [u8; 129] {
        let mut pks = [0u8; 129];
        pks[..65]
            .copy_from_slice(&self.private_key.public_key().to_sec1_bytes());

        debug!("Public Key: {}", to_hex(&pks[..65]));

        let signature: Signature = self.signing_key.sign(&pks[..65]);
        pks[65..].copy_from_slice(&signature.to_bytes());

        debug!("Public Key Signature: {}", to_hex(&pks[65..]));

        pks
    }

    pub fn receive(
        &mut self,
        pub_key: &[u8],
    ) -> Result<Aes256, HandshakeError> {
        debug!("Received Public Key + Signature");

        if pub_key.len() != 129 {
            return Err(HandshakeError::PubKeyLengthInvalidLength);
        }

        debug!("Public Key + Signature Length Verified!");

        self.signing_key
            .verifying_key()
            .verify(&pub_key[..65], &Signature::from_slice(&pub_key[65..])?)?;

        debug!("Public Key Signature Verified!");

        let shared_secret = self
            .private_key
            .diffie_hellman(&PublicKey::from_sec1_bytes(&pub_key[..65])?);

        debug!(
            "Shared Secret: {}",
            to_hex(&shared_secret.raw_secret_bytes().to_vec())
        );

        let h = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());

        let mut enc_key = [0; 32];
        h.expand(&[0; 32], &mut enc_key)
            .map_err(|_| HandshakeError::HkdfKeyInvalidLength)?;

        debug!("Encryption Key: {}", to_hex(&enc_key));

        Ok({
            use aes::cipher::KeyInit;
            Aes256::new_from_slice(&enc_key)?
        })
    }
}
