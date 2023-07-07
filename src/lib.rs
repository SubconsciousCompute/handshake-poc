#[cfg(test)]
mod tests {
    use aes::{
        cipher::{BlockDecrypt, BlockEncrypt},
        Aes256, Block,
    };
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use p256::ecdh::EphemeralSecret;
    use rand::{thread_rng, Rng};
    use rand_core::OsRng;
    use sha2::Sha256;

    #[test]
    fn handshake() {
        let pre_shared_key: [u8; 32] = thread_rng().gen();

        let a_priv_key = EphemeralSecret::random(&mut OsRng);
        let a_pub_key = a_priv_key.public_key();

        let b_priv_key = EphemeralSecret::random(&mut OsRng);
        let b_pub_key = b_priv_key.public_key();

        let a_shared_secret = a_priv_key.diffie_hellman(&b_pub_key);
        let b_shared_secret = b_priv_key.diffie_hellman(&a_pub_key);

        assert_eq!(
            a_shared_secret.raw_secret_bytes(),
            b_shared_secret.raw_secret_bytes()
        );

        let h = Hkdf::<Sha256>::new(None, a_shared_secret.raw_secret_bytes());

        let mut enc_key = [0u8; 32];
        let mut chan_bind_token = [0u8; 32];

        assert!(h.expand(&[0; 32], &mut enc_key).is_ok());
        assert!(h.expand(&[1; 32], &mut chan_bind_token).is_ok());

        let auth_msg = Hmac::<Sha256>::new_from_slice(&chan_bind_token)
            .unwrap()
            .chain_update(pre_shared_key)
            .finalize()
            .into_bytes();

        let mut encrypted = auth_msg;

        let cipher = {
            use aes::cipher::KeyInit;
            Aes256::new_from_slice(&enc_key).unwrap()
        };

        for chunk in encrypted.chunks_mut(16) {
            cipher.encrypt_block(Block::from_mut_slice(chunk))
        }

        let mut decrypted = encrypted;

        for chunk in decrypted.chunks_mut(16) {
            cipher.decrypt_block(Block::from_mut_slice(chunk))
        }

        assert_eq!(auth_msg, decrypted);
    }
}
