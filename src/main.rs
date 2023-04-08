use std::fs::File;
use std::io::Write;

use rsa::{
    pkcs8::{LineEnding, EncodePublicKey, EncodePrivateKey},
    RsaPrivateKey, RsaPublicKey,
};

/// Creates key pairs
fn create_key_pairs() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();

    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    (private_key, public_key)
}

/// Writes key pairs to disk. Will panic on error. 
fn write_keys_to_disk(priv_key: RsaPrivateKey, pub_key: RsaPublicKey) {
    let priv_key_pem = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let pub_key_pem = pub_key.to_public_key_pem(LineEnding::LF).unwrap();

    let mut file = File::create("priv_key.pem").expect("Unable to private key pem.");
    file.write_all(priv_key_pem.as_bytes()).expect("Unable to write to private key pem.");

    file = File::create("pub_key.pem").expect("Unable to create public key pem.");
    file.write_all(pub_key_pem.as_bytes()).expect("Unable to write to public key pem.");
}

fn main() {
    // Create key pairs
    let (priv_key, pub_key) = create_key_pairs();

    // Save key pairs
    write_keys_to_disk(priv_key, pub_key);
}
