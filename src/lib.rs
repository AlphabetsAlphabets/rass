//! A crate that uses the already well established [rsa](https://docs.rs/rsa/0.8.2/rsa/) and
//! [pkcs8](https://docs.rs/pkcs8/0.10.2/pkcs8/) crates to provide a simple plug
//! and play experience.
//!
//! # Usage
//! ## Saving key pairs
//! ```ignore
//! // The values passed in will be the file names of the private and public keys.
//! let keys = Keys::new("priv", "pub");
//! // Saves the key pairs to a folder in the cwd called keys and encrypts the private key with a
//! // password
//! keys.write_to_disk("password", "path/where/keys/are/saved");
//! ```
//!
//! ## Using an existing key pair
//! ```ignore
//! let keys = Keys::retrieve_keys("path/to/private/key", "password", "path/to/public/key")?;
//! let ciphertext = keys.seal(b"hi")?;
//! let plaintext = keys.unseal(ciphertext)?;
//! ```

pub mod errors;

mod test;

use std::fs;

use errors::KeyError;
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{errors::Result as RsaResult, Pkcs1v15Encrypt, PublicKey, RsaPrivateKey, RsaPublicKey};

/// Contains the key pairs and their names. This struct is to use the key pairs and to retrieve
/// them. It can also be used to create new key pairs.
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

    /// Will read the PEM encoded keys and return `Self`.
    /// # Parameters
    /// - `priv_key`: Path to private key file.
    /// - `password`: The password used to encrypt the private key.
    /// - `pub_key`: Path to public key file.
    pub fn retreive_keys(
        priv_key_path: &'names str,
        password: &str,
        pub_key_path: &'names str,
    ) -> Result<Self, KeyError> {
        // Get *encrypted* private key first
        let mut pem = fs::read_to_string(priv_key_path)?;

        // Decrypt encrypted private key
        let priv_key = RsaPrivateKey::from_pkcs8_encrypted_pem(&pem, password)?;
        pem.clear();

        // Then get public key
        pem = fs::read_to_string(pub_key_path)?;
        let pub_key = RsaPublicKey::from_public_key_pem(&pem)?;

        Ok(Self {
            priv_key,
            priv_key_name: priv_key_path,
            pub_key,
            pub_key_name: pub_key_path,
        })
    }
}

impl Keys<'_> {
    /// Will further encrypt the `self.priv_key` before writing it to disk.
    /// Both keys will be PEM encoded.
    /// # Parameters
    /// - `priv_key_pass`: The password used to encrypt the private key.
    /// - `folder`: The folder to write the keys to. If left empty will default to cwd.
    pub fn write_to_disk(&self, priv_key_pass: &str, folder: &str) -> Result<(), KeyError> {
        let folder = if folder.is_empty() { "." } else { folder };

        let priv_key_pem = self.priv_key.to_pkcs8_encrypted_pem(
            &mut rand::thread_rng(),
            priv_key_pass,
            LineEnding::LF,
        )?;

        let pub_key_pem = self.pub_key.to_public_key_pem(LineEnding::LF)?;

        let priv_key_path = format!("{}/{}", folder, self.priv_key_name);
        fs::write(priv_key_path, priv_key_pem.as_bytes())?;

        let pub_key_path = format!("{}/{}", folder, self.pub_key_name);
        fs::write(pub_key_path, pub_key_pem.as_bytes())?;

        Ok(())
    }

    pub fn seal(&self, plaintext: &[u8]) -> RsaResult<Vec<u8>> {
        let mut rng = rand::thread_rng();
        self.pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
    }

    pub fn unseal(&self, ciphertext: &[u8]) -> RsaResult<Vec<u8>> {
        self.priv_key.decrypt(Pkcs1v15Encrypt, ciphertext)
    }
}
