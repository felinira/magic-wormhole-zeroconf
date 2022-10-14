use crate::control::message::{DecryptedMessage, EncryptedMessage};
use crate::control::server::ConnectionError;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, KeyInit};

#[derive(Clone)]
pub struct MessageCipher {
    cipher: chacha20poly1305::ChaCha20Poly1305,
}

impl MessageCipher {
    pub fn from_secret(secret: &[u8]) -> Self {
        let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(secret).unwrap();
        Self { cipher }
    }

    pub fn from_cipher(cipher: chacha20poly1305::ChaCha20Poly1305) -> Self {
        Self { cipher }
    }

    pub fn encrypt_message(
        &mut self,
        message: &DecryptedMessage,
    ) -> Result<EncryptedMessage, ConnectionError> {
        let mut rng = rand::rngs::OsRng;
        let nonce = chacha20poly1305::ChaCha20Poly1305::generate_nonce(&mut rng);
        let serialized_message = serde_json::to_string(message)?;
        let data = self
            .cipher
            .encrypt(&nonce, serialized_message.as_bytes())
            .map_err(|_| ConnectionError::CryptoError)?;

        Ok(EncryptedMessage {
            nonce: nonce.to_vec(),
            data,
        })
    }

    pub fn decrypt_message(
        &mut self,
        message: &EncryptedMessage,
    ) -> Result<DecryptedMessage, ConnectionError> {
        let nonce = chacha20poly1305::Nonce::from_slice(&message.nonce);
        let decrypted_data = self
            .cipher
            .decrypt(nonce, &*message.data)
            .map_err(|_| ConnectionError::CryptoError)?;
        Ok(serde_json::from_slice(&decrypted_data)?)
    }
}
