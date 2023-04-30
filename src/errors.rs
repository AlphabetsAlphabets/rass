//! A few error conversions into a custom error type.

use std::{
    env,
    error::Error,
    fmt::{Debug, Display},
    io,
};

use pkcs8::spki;
use rsa::errors::Error as RsaError;

#[derive(Debug)]
pub enum KeyError {
    KeyNotFound(String),
    PrivateKeyDecryptionFailed(String),
    PemDecryptionFailed(String),
    /// Errors when `write_to_disk` is called and `self.priv_key`
    /// and `self.pub_key` are `None`.
    UnableToUnpackKey,
    /// Errors when `seal` is called but `self.priv_key` is `None`.
    PrivateKeyNoLoaded,
    EncryptionFailed,
    DecryptionFailed,
}

impl Error for KeyError {}

impl Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use KeyError::*;

        let msg = r#"Private key or public is not loaded. Make sure to call one of the retrieve methods:
- Keys::retrieve_keys
- Keys::retrieve_private_key
- Or create new pairs directly with Keys::new()
"#;

        let msg = match self {
        KeyNotFound(msg) => format!("Key not found: {msg}"),
        PrivateKeyDecryptionFailed(msg) => format!("Key decryption failed: {msg}"),
        PemDecryptionFailed(msg) => format!("Pem decryption failed: {msg}"),
        UnableToUnpackKey => String::from(msg),
        PrivateKeyNoLoaded => String::from("You tried to call `seal` without properly loading the key pairs."),
        EncryptionFailed => String::from("Encryption failed. Check your public key."),
        DecryptionFailed => String::from("Decryption failed. Check your private key."),
    };

        write!(f, "{}", msg)
    }
}

impl From<io::Error> for KeyError {
    fn from(value: io::Error) -> Self {
        let current_dir = env::current_dir().unwrap();
        let current_dir = current_dir.to_str().unwrap();
        let msg = format!(
            "\n{}. You ran 'cargo run' in {}",
            value.to_string(),
            current_dir
        );

        Self::KeyNotFound(msg)
    }
}

impl From<pkcs8::Error> for KeyError {
    fn from(value: pkcs8::Error) -> Self {
        Self::PrivateKeyDecryptionFailed(value.to_string())
    }
}

impl From<spki::Error> for KeyError {
    fn from(value: spki::Error) -> Self {
        Self::PemDecryptionFailed(value.to_string())
    }
}

impl From<RsaError> for KeyError {
    fn from(value: RsaError) -> Self {
        Self::PemDecryptionFailed(value.to_string())
    }
}
