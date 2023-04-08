use std::fs::File;
use std::io::{Write, Read};
use std::string::FromUtf8Error;

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use pkcs8::{EncodePrivateKey, DecodePrivateKey, DecodePublicKey, EncodePublicKey, LineEnding};
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
    pub_key: RsaPublicKey,
    pub_key_name: &str,
) {
    // Encode in PKCS8 and print the keys
    let priv_key_pem = priv_key
        .to_pkcs8_encrypted_pem(&mut rand::thread_rng(), "password", LineEnding::LF)
        .unwrap();
    let pub_key_pem = pub_key.to_public_key_pem(LineEnding::LF).unwrap();

    let mut file = File::create(priv_key_name).expect("Unable to create private key pem.");
    file.write_all(priv_key_pem.as_bytes()).unwrap();

    file = File::create(pub_key_name).expect("Unable to create pub key pem.");
    file.write_all(pub_key_pem.as_bytes()).unwrap();
}

/// Encrypts data with the public key key.
fn seal(priv_key: &RsaPublicKey, plaintext: &str) -> Vec<u8> {
    // Generate a new key for each payload
    let key = Aes256Gcm::generate_key(&mut rand::thread_rng());
    let cipher = Aes256Gcm::new(&key);

    // And a random nonce
    let nonce = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce);

    // Encrypt the payload and the key
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
    let key = priv_key
        .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &key)
        .unwrap();

    // Chunk it all together into a single vec
    let mut buf = Vec::with_capacity(key.len() + nonce.len() + ciphertext.len());
    buf.extend(key);
    buf.extend(nonce);
    buf.extend(ciphertext);

    buf
}

fn open(skey: &RsaPrivateKey, ciphertext: &[u8]) -> Result<String, FromUtf8Error> {
    // We have a 128 byte key, 12 byte nonce, and some data. So let's do some safety checks before
    // we slice away.
    if ciphertext.len() < 140 {
        panic!("encrypted content is too small");
    }

    // Parse back the key and nonce
    let key = skey.decrypt(Pkcs1v15Encrypt, &ciphertext[..128]).unwrap();
    let nonce = Nonce::from_slice(&ciphertext[128..140]);

    // Create the cipher and decrypt
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let plaintext = cipher.decrypt(nonce, &ciphertext[140..]).unwrap();

    // Parse back into a string
    String::from_utf8(plaintext)
}

/// # Parameters
/// `priv_key` - Path to private key file.
/// `pub_key` - Path to public key file.
fn retreive_keys(priv_key: &str, password: &str, pub_key: &str) -> (RsaPrivateKey, RsaPublicKey) {
    // Get private key
    let mut file = File::open(priv_key).expect("Unable to find private key.");
    let mut content = String::new();

    file.read_to_string(&mut content).unwrap();
    let priv_key: RsaPrivateKey = DecodePrivateKey::from_pkcs8_encrypted_pem(&content, password).unwrap();
    content.clear();

    // Get public key
    file = File::open(pub_key).expect("Unable to find public key.");
    file.read_to_string(&mut content).unwrap();
    let pub_key: RsaPublicKey = DecodePublicKey::from_public_key_pem(&content).unwrap();

    (priv_key, pub_key)
}

fn main() {
    println!("Retrieving keys.");
    let (priv_key, pub_key) = retreive_keys("ultimate.sec.pem", "password", "ultimate.pub.pem");

    let digest = seal(&pub_key, "Hello!");
    let plaintext = open(&priv_key, digest.as_slice()).unwrap();
    println!("Plaintext: {}", plaintext);
}
