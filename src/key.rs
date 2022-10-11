/// The verification flow is based on the matrix key verification flow as detailed
/// [here](https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing)
use crate::control::PeerInfo;
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Debug)]
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
    pub fn new(our_key: &str, our_info: &PeerInfo, their_key: &str, their_info: &PeerInfo) -> Self {
        let our_sas_info = format!("{}|{}", our_key, our_info.session_id);
        let their_sas_info = format!("{}|{}", their_key, their_info.session_id);

        let sas_string = format!(
            "MAGIC_WORMHOLE_ZEROCONF_VERIFICATION_SAS|{}|{}",
            our_sas_info, their_sas_info
        );

        println!("sas string: {}", sas_string);

        let hkdf_sha265 = Self::generate_hkdf(&sas_string);

        Self { hkdf_sha265 }
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
    pub fn get_emoji_string(&self, length: usize) -> String {
        let byte_input = &self.hkdf_sha265;
        let mut output_string = String::new();
        let mut debug_string = String::new();

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
                debug_string.push_str(&format!("{emoji} ({emoji_name}) "));

                // cleanup
                table_index = 0;
            }
        }

        println!("{debug_string}");

        output_string
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
    use crate::control::PeerInfo;
    use crate::key::Sas;

    #[test]
    fn test_sas() {
        let our_key = "1234";
        let their_key = "9876";

        let our_info = PeerInfo::new(
            "test1".to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            None,
        );
        let their_info = PeerInfo::new(
            "test2".to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            None,
        );

        let sas = Sas::new(our_key, &our_info, their_key, &their_info);

        println!("Sas: {:?}", sas);

        let emoji_string = sas.get_emoji_string(6);

        println!("Emoji: {}", emoji_string);
    }
}
