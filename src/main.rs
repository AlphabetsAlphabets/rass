use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{Pkcs1v15Encrypt, PublicKey, RsaPrivateKey, RsaPublicKey};

mod tests;

/// Creates key pairs
fn create_key_pairs() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();

    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    (private_key, public_key)
}

/// Writes key pairs to disk. The private and public keys will have a name.
/// These names are the file names where the keys are stored with the `.pem` extension.
fn write_keys_to_disk(
    priv_key: RsaPrivateKey,
    priv_key_name: &str,
    priv_key_pass: &str,
    pub_key: RsaPublicKey,
    pub_key_name: &str,
) {
    let priv_key_pem = priv_key
        .to_pkcs8_encrypted_pem(&mut rand::thread_rng(), priv_key_pass, LineEnding::LF)
        .unwrap();
    let pub_key_pem = pub_key.to_public_key_pem(LineEnding::LF).unwrap();

    let mut file = File::create(priv_key_name).expect("Unable to create private key pem.");
    file.write_all(priv_key_pem.as_bytes()).unwrap();

    file = File::create(pub_key_name).expect("Unable to create pub key pem.");
    file.write_all(pub_key_pem.as_bytes()).unwrap();
}

/// # Parameters
/// `priv_key` - Path to private key file.
/// `pub_key` - Path to public key file.
fn retreive_keys(priv_key_path: &str, password: &str, pub_key_path: &str) -> (RsaPrivateKey, RsaPublicKey) {
    let enc_priv_key = Path::new(priv_key_path);

    // Get *encrypted* private key
    let mut file = File::open(enc_priv_key).expect("Unable to find private key.");
    let mut content = String::new();

    file.read_to_string(&mut content).unwrap();

    // Decrypt encrypted private key
    let priv_key = RsaPrivateKey::from_pkcs8_encrypted_pem(&content, password).unwrap();
    content.clear();

    // Get public key
    file = File::open(pub_key_path).expect("Unable to find public key.");
    file.read_to_string(&mut content).unwrap();
    let pub_key = RsaPublicKey::from_public_key_pem(&content).unwrap();

    (priv_key, pub_key)
}


fn seal(pub_key: &RsaPublicKey, plaintext: &[u8]) -> rsa::errors::Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
}

fn unseal(priv_key: &RsaPrivateKey, ciphertext: &[u8]) -> rsa::errors::Result<Vec<u8>> {
    priv_key.decrypt(Pkcs1v15Encrypt, ciphertext)
}

fn main() {
    let (priv_key, pub_key) = retreive_keys("ulti.priv.pem", "password", "ulti.pub.pem");
    let ciphertext = seal(&pub_key, b"hi").unwrap();
    let plaintext = unseal(&priv_key, &ciphertext).unwrap();
    let plaintext = String::from_utf8(plaintext).unwrap();
    println!("{}", plaintext);
}
