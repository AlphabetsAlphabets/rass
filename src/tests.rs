#[cfg(test)]
mod tests {
    use crate::Keys;

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
