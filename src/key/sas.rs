/// The verification flow is based on the matrix key verification flow as detailed
/// [here](https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing)
use crate::control::message::PeerInfoMessage;
use hkdf::Hkdf;
use sha2::Digest;
use sha2::Sha256;

pub struct Sas {
    hkdf_sha265: [u8; 42],
}

impl Sas {
    /// Generate the SAS info
    ///
    /// SAS stands for "Short Authentication String" and is a method for emoji verification of generated
    /// key pairs
    ///
    /// This uses the key derived in the key exchange in addition to the session id stored in the
    /// PeerInfo structs to generate a strong SAS
    pub fn new_hkdf_sha265(
        shared_key: &[u8],
        our_key: &[u8],
        their_key: &[u8],
        client: bool,
    ) -> Self {
        let shared_key_hash = Self::hash_sha256(shared_key);
        let our_key_hash = Self::hash_sha256(our_key);
        let their_key_hash = Self::hash_sha256(their_key);

        let combined_sas_info = if client {
            format!("{}|{}", our_key_hash, their_key_hash)
        } else {
            format!("{}|{}", their_key_hash, our_key_hash)
        };

        let sas_string = format!(
            "MAGIC_WORMHOLE_ZEROCONF_VERIFICATION_SAS|{}|{}",
            shared_key_hash, combined_sas_info
        );

        println!("sas string: {}", sas_string);

        let hkdf_sha265 = Self::generate_hkdf(&sas_string);

        Self { hkdf_sha265 }
    }

    fn hash_sha256(data: &[u8]) -> String {
        // create a Sha256 object
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash_data = hasher.finalize();
        hex::encode(hash_data)
    }

    fn generate_hkdf(input: &str) -> [u8; 42] {
        let hk = Hkdf::<Sha256>::new(None, &input.as_bytes());

        // 42 bytes for sha265
        let mut okm = [0u8; 42];
        hk.expand(&[], &mut okm)
            .expect("42 is a valid length for Sha256 to output");
        okm
    }

    /// Length can be between 1 and 85
    ///
    /// *Panics*
    ///
    /// When length is > 85 this function will panic
    pub fn get_emoji_string(&self, length: usize) -> (String, String) {
        let byte_input = &self.hkdf_sha265;
        let mut output_string = String::new();
        let mut verbose_string = String::new();

        let mut table_index = 0;

        // each emoji index is 6 bits wide
        for i in 0..(length * 6) {
            let offset_byte = i / 8;
            let offset_bit = (i % 8) as u8;
            let emoji_offset = (i % 6) as u8;

            let bit = (byte_input[offset_byte] & (1 << offset_bit)) >> offset_bit;
            table_index |= bit << emoji_offset;

            if i % 6 == 5 {
                // last bit of this char
                let (emoji, emoji_name) = EMOJI_TABLE[table_index as usize];

                output_string.push_str(emoji);
                verbose_string.push_str(&format!("{emoji} ({emoji_name}) "));

                // cleanup
                table_index = 0;
            }
        }

        (output_string, verbose_string)
    }
}

/// This table is taken from the matrix documentation
/// https://spec.matrix.org/latest/client-server-api/#sas-method-emoji
const EMOJI_TABLE: [(&str, &str); 64] = [
    ("\u{1F436}", "Dog"),
    ("\u{1F431}", "Cat"),
    ("\u{1F981}", "Lion"),
    ("\u{1F40E}", "Horse"),
    ("\u{1F984}", "Unicorn"),
    ("\u{1F437}", "Pig"),
    ("\u{1F418}", "Elephant"),
    ("\u{1F430}", "Rabbit"),
    ("\u{1F43C}", "Panda"),
    ("\u{1F413}", "Rooster"),
    ("\u{1F427}", "Penguin"),
    ("\u{1F422}", "Turtle"),
    ("\u{1F41F}", "Fish"),
    ("\u{1F419}", "Octopus"),
    ("\u{1F98B}", "Butterfly"),
    ("\u{1F337}", "Flower"),
    ("\u{1F333}", "Tree"),
    ("\u{1F335}", "Cactus"),
    ("\u{1F344}", "Mushroom"),
    ("\u{1F30F}", "Globe"),
    ("\u{1F319}", "Moon"),
    ("\u{2601}\u{FE0F}", "Cloud"),
    ("\u{1F525}", "Fire"),
    ("\u{1F34C}", "Banana"),
    ("\u{1F34E}", "Apple"),
    ("\u{1F353}", "Strawberry"),
    ("\u{1F33D}", "Corn"),
    ("\u{1F355}", "Pizza"),
    ("\u{1F382}", "Cake"),
    ("\u{2764}\u{FE0F}", "Heart"),
    ("\u{1F600}", "Smiley"),
    ("\u{1F916}", "Robot"),
    ("\u{1F3A9}", "Hat"),
    ("\u{1F453}", "Glasses"),
    ("\u{1F527}", "Spanner"),
    ("\u{1F385}", "Santa"),
    ("\u{1F44D}", "Thumbs Up"),
    ("\u{2602}\u{FE0F}", "Umbrella"),
    ("\u{231B}", "Hourglass"),
    ("\u{23F0}", "Clock"),
    ("\u{1F381}", "Gift"),
    ("\u{1F4A1}", "Light Bulb"),
    ("\u{1F4D5}", "Book"),
    ("\u{270F}\u{FE0F}", "Pencil"),
    ("\u{1F4CE}", "Paperclip"),
    ("\u{2702}\u{FE0F}", "Scissors"),
    ("\u{1F512}", "Lock"),
    ("\u{1F511}", "Key"),
    ("\u{1F528}", "Hammer"),
    ("\u{260E}\u{FE0F}", "Telephone"),
    ("\u{1F3C1}", "Flag"),
    ("\u{1F682}", "Train"),
    ("\u{1F6B2}", "Bicycle"),
    ("\u{2708}\u{FE0F}", "Aeroplane"),
    ("\u{1F680}", "Rocket"),
    ("\u{1F3C6}", "Trophy"),
    ("\u{26BD}", "Ball"),
    ("\u{1F3B8}", "Guitar"),
    ("\u{1F3BA}", "Trumpet"),
    ("\u{1F514}", "Bell"),
    ("\u{2693}", "Anchor"),
    ("\u{1F3A7}", "Headphones"),
    ("\u{1F4C1}", "Folder"),
    ("\u{1F4CC}", "Pin"),
];

#[cfg(test)]
mod test {
    use super::Sas;
    use crate::control::message::PeerInfoMessage;

    #[test]
    fn test_sas() {
        let our_key = "1234";
        let their_key = "9876";

        let our_info = PeerInfoMessage::new(
            "test1".to_string(),
            "7844286e-e00c-46a7-8f97-4a5139ca7c32".to_string(),
            None,
            None,
        );
        let their_info = PeerInfoMessage::new(
            "test2".to_string(),
            "f6aaae29-51c7-40d6-b406-bec5d497a807".to_string(),
            None,
            None,
        );

        let sas = Sas::new_hkdf_sha265(our_key, &our_info, their_key, &their_info);
        let emoji_string = sas.get_emoji_string(6);
        assert_eq!(emoji_string, "🐓🌽✂️⏰☁️🔑");

        println!("Emoji: {}", emoji_string);
    }
}
