use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{Pkcs1v15Encrypt, PublicKey, RsaPrivateKey, RsaPublicKey};

mod tests;

pub struct Keys<'names> {
    priv_key: RsaPrivateKey,
    priv_key_name: &'names str,
    pub_key: RsaPublicKey,
    pub_key_name: &'names str,
}

impl<'names> Keys<'names> {
    /// Creates key pairs.
    /// # Parameters
    /// - `priv_key_name` & `pub_key_name`: The name of the keys. If the keys are saved to disk
    /// with `self.write_to_disk` the values for these variables will be the file name. 
    pub fn new(priv_key_name: &'names str, pub_key_name: &'names str) -> Self {
        let mut rng = rand::thread_rng();

        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let pub_key = RsaPublicKey::from(&priv_key);

        Self {
            priv_key,
            priv_key_name,
            pub_key,
            pub_key_name,
        }
    }

    /// # Parameters
    /// `priv_key` - Path to private key file.
    /// `pub_key` - Path to public key file.
    pub fn retreive_keys(priv_key_path: &'names str, password: &str, pub_key_path: &'names str) -> Self {
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

        Self {
            priv_key,
            priv_key_name: priv_key_path,
            pub_key,
            pub_key_name: pub_key_path,
        }
    }
}

impl Keys<'_> {
    /// Will further encrypt the `self.priv_key` before writing it to disk.
    /// Both keys will be PEM encoded.
    /// # Parameters
    /// - `priv_key_pass`: The password used to encrypt the private key.
    /// - `folder`: The folder to write the keys to. If left empty will default to cwd.
    pub fn write_to_disk(&self, priv_key_pass: &str, folder: &str) {
        let folder = if folder.is_empty() {
            "."
        } else {
            folder
        };

        let priv_key_pem = self
            .priv_key
            .to_pkcs8_encrypted_pem(&mut rand::thread_rng(), priv_key_pass, LineEnding::LF)
            .unwrap();
        let pub_key_pem = self.pub_key.to_public_key_pem(LineEnding::LF).unwrap();

        let priv_key_path = format!("{}/{}", folder, self.priv_key_name);
        let mut file = File::create(priv_key_path).expect("Unable to create private key pem.");
        file.write_all(priv_key_pem.as_bytes()).unwrap();

        let pub_key_path = format!("{}/{}", folder, self.pub_key_name);
        file = File::create(pub_key_path).expect("Unable to create pub key pem.");
        file.write_all(pub_key_pem.as_bytes()).unwrap();
    }

    pub fn seal(&self, plaintext: &[u8]) -> rsa::errors::Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        self.pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
    }

    pub fn unseal(&self, ciphertext: &[u8]) -> rsa::errors::Result<Vec<u8>> {
        self.priv_key.decrypt(Pkcs1v15Encrypt, ciphertext)
    }
}
