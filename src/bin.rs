use srsa::Keys;
use srsa::errors::KeyError;

fn main() -> Result<(), KeyError> {
    Keys::retreive_keys("pub", "123", "pem")?;
    Ok(())
}
