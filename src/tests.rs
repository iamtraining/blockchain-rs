use std::fs;
use std::os::unix::prelude::OsStrExt;

#[test]
fn test_write() {
    super::write(2, "Den", "Nis", 228).unwrap();
}

#[test]
fn test_last_block() {
    if let Ok(max) = super::last_block("./testdata") {
        assert_eq!(max, 1_u64);
    };
}

#[test]
fn test_get_file_bytes() {
    if let Ok(buf) = fs::read("./testdata/1.json") {
        let s = match std::str::from_utf8(&buf) {
            Ok(v) => {
                println!("{}", v);
                assert_eq!(v, "test_get_file_bytes");
            }
            Err(e) => panic!("invalid utf-8 sequence: {}", e),
        };
    };
}

#[test]
fn test_create_file_name() {
    let path = super::format_block_file_name(222);
    assert_eq!(path.as_os_str().as_bytes(), b"./data/222.json")
}

#[test]
fn test_block_serialize() {
    let block = super::Block::new("Den", "Nis", 228, String::new());
    if let Ok(b) = serde_json::to_string_pretty(&block) {
        println!("{}", b)
    };
}

#[test]
fn test_block_deserialize() {
    let s = r#"{
        "from": "Den",
        "to": "Nis",
        "sum": 228,
        "hash": ""
      }"#;

    if let Ok(block) = serde_json::from_slice::<'_, super::Block>(s.as_bytes()) {
        assert_eq!(block.from, "Den");
        assert_eq!(block.to, "Nis");
        assert_eq!(block.sum, 228);
        assert_eq!(block.hash, "");
        println!("{:?}", block);
    }
}

#[test]
fn test_new_hash() {
    let s = super::new_hash("message");
    assert_eq!(
        s,
        "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d"
    );
}
