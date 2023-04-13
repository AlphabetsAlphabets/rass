//! A few error conversions into a custom error type.

use std::{io, fmt::Display};

use rsa::errors::Error as RsaError;
use pkcs8::spki;

pub enum KeyError {
    KeyNotFound(String),
    PrivateKeyDecryptionFailed(String),
    PemDecryptionFailed(String),
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
        Self::KeyNotFound(value.to_string())
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
