use ed25519_dalek::ed25519::signature::Signature;
use ed25519_dalek::{Signer, Verifier};

pub struct DeviceKeyPair {
    keypair: ed25519_dalek::Keypair,
}

impl DeviceKeyPair {
    pub fn generate_new_ed25519() -> Self {
        let mut csprng = rand_07::rngs::OsRng {};
        let keypair: ed25519_dalek::Keypair = ed25519_dalek::Keypair::generate(&mut csprng);

        Self { keypair }
    }

    pub fn public_key(&self) -> DevicePublicKey {
        DevicePublicKey::from_data(self.keypair.public.as_bytes()).unwrap()
    }

    pub fn sign(&mut self, message: &[u8]) -> Vec<u8> {
        self.keypair.sign(message).as_bytes().to_vec()
    }
}

pub struct DevicePublicKey {
    public_key: ed25519_dalek::PublicKey,
}

impl DevicePublicKey {
    pub fn from_data(bytes: &[u8]) -> Option<Self> {
        let public_key = ed25519_dalek::PublicKey::from_bytes(bytes).ok()?;

        Some(Self { public_key })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> bool {
        if let Ok(signature) = ed25519_dalek::Signature::from_bytes(signature_bytes) {
            self.public_key.verify(message, &signature).is_ok()
        } else {
            false
        }
    }

    /*pub fn from_fingerprint(fingerprint: &str) -> Option<Self> {
        let hex_data = fingerprint.strip_prefix("ED25519:")?;
        let key_data = hex::decode(hex_data).ok()?;
        let public_key = ed25519_dalek::PublicKey::from_bytes(&key_data).ok()?;

        Some(Self { public_key })
    }

    pub fn fingerprint(&self) -> String {
        format!("ED25519:{}", hex::encode(&self.public_key))
    }*/
}

#[cfg(test)]
mod test {
    use super::DeviceKeyPair;
    use crate::key::device::DevicePublicKey;

    /*#[test]
    fn test_serialize_fingerprint() {
        let keypair = DeviceKeyPair::generate_new_ed25519();
        let bytes = keypair.keypair.public.as_bytes();

        let pubkey = keypair.public_key();
        let fingerprint = pubkey.fingerprint();
        let pubkey2 = DevicePublicKey::from_fingerprint(&fingerprint).unwrap();
        assert_eq!(pubkey2.public_key.as_bytes(), bytes);
    }*/
}
