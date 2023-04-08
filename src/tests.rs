#[cfg(test)]
mod tests {
    use crate::{retreive_keys, create_key_pairs, write_keys_to_disk};

    #[test]
    #[should_panic]
    fn pem_don_t_exist() {
        retreive_keys("WEEE", "wrong_pass", "XXX");
    }

    #[test]
    #[should_panic]
    fn pem_exist_wrong_pass() {
        retreive_keys("ultimate.sec.pem", "wrong_pass", "ultimate.pub.pem");
    }

    #[test]
    fn create_keys() {
        create_key_pairs();
    }

    #[test]
    fn save_keys() {
        let (priv_key, pub_key) = create_key_pairs();
        write_keys_to_disk(priv_key, "test.sec.pem", pub_key, "test.pub.pem");
    }
}
