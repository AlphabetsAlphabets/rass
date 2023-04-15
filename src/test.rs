#[cfg(test)]
mod test {
    use crate::Keys;

    #[test]
    #[should_panic]
    fn check_if_key_exists() {
        Keys::retreive_keys("d", "d", "d").unwrap();
    }

    #[test]
    fn retrieve_existing_keys() {
        Keys::retreive_keys("keys/test_priv", "1234", "keys/test_pub").unwrap();
    }
}
