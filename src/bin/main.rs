use keys::Keys;

fn main() {
    let keys = Keys::new("test2.sec.pem", "test2.pub.pem");
    let ciphertext = keys.seal(b"XXX").unwrap();
    let plaintext = String::from_utf8(keys.unseal(&ciphertext).unwrap()).unwrap();
    println!("{}", plaintext);
}
