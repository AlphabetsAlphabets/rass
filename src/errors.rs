//! A few error conversions into a custom error type.

use std::{
    fmt::{Debug, Display},
    io, env,
};

use pkcs8::spki;
use rsa::errors::Error as RsaError;

pub enum KeyError {
    KeyNotFound(String),
    PrivateKeyDecryptionFailed(String),
    PemDecryptionFailed(String),
}

impl Debug for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use KeyError::*;

        let msg = match self {
            // Find out the directory the user passed in and the current directory.
            KeyNotFound(msg) => format!("Key not found: {msg}"),
            PrivateKeyDecryptionFailed(msg) => format!("Key decryption failed: {msg}"),
            PemDecryptionFailed(msg) => format!("Pem decryption failed: {msg}"),
        };

        write!(f, "{}", msg)
    }
}

impl Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use KeyError::*;

        let msg = match self {
            KeyNotFound(msg) => format!("Key not found: {msg}"),
            PrivateKeyDecryptionFailed(msg) => format!("Key decryption failed: {msg}"),
            PemDecryptionFailed(msg) => format!("Pem decryption failed: {msg}"),
        };

        write!(f, "{}", msg)
    }
}

impl From<io::Error> for KeyError {
    fn from(value: io::Error) -> Self {
        let current_dir = env::current_dir().unwrap();
        let current_dir = current_dir.to_str().unwrap();
        let msg = format!("\n{}. You ran 'cargo run' in {}", value.to_string(), current_dir);

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
