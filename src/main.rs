mod des;
mod structs;

fn main() {
    let des = des::DES::new();
    let plaintext: [u8; 8] = [b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a'];
    let key: [u8; 8] = [b'b', b'b', b'b', b'b', b'b', b'b', b'b', b'b'];
    let cipher = des.encrypt(plaintext, key, 16);
    println!("{:?}", cipher);
}
