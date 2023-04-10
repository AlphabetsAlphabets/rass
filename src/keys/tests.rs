#[cfg(test)]
mod tests {
    use crate::Keys;

    #[test]
    #[should_panic]
    fn pem_don_t_exist() {
        Keys::retreive_keys("WEEE", "wrong_pass", "XXX");
    }

    #[test]
    fn create_keys() {
        Keys::new("test.priv.pem", "test.pub.pem");
    }

    #[test]
    fn create_and_write_keys() {
        let keys = Keys::new("test.priv.pem", "test.pub.pem");
        keys.write_to_disk("test", "tests/");
    }

    #[test]
    fn save_keys() {
    }
}
