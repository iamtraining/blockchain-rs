#![allow(dead_code, unused_variables, unused_imports)]
use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::{File, OpenOptions};

use std::convert;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str;
use std::usize;

const DIR: &str = "./data";
const READ: &str = "read";
const WRITE: &str = "write";
const EXTENSION: &str = ".json";
const BUFF: u16 = 1024;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Serialize, Deserialize, Debug)]
pub struct Block {
    from: String,
    to: String,
    sum: u64,
    hash: String,
}

fn main() {
    if let Err(err) = fs::create_dir_all(DIR) {
        exit_with_err(err.into());
    };

    if let Err(err) = run() {
        exit_with_err(err);
    }
}

fn run() -> Result<(), BoxError> {
    let m = Command::new("blockchain")
        .author("me")
        .version("0.0.1")
        .about("rawr xd")
        .arg(Arg::new(READ).long(READ).short('r').takes_value(false))
        .arg(
            Arg::new(WRITE)
                .long(WRITE)
                .short('w')
                .takes_value(true)
                .allow_invalid_utf8(true)
                .default_value(DIR),
        )
        .get_matches();

    let last = last_block(m.value_of(WRITE).unwrap())?;
    println!("last block {}", last);

    if m.is_present(READ) {
        read(last)?;
        return Ok(());
    }

    if m.is_present(WRITE) {
        write(last, "Den".to_owned(), "Nis".to_owned(), 228)?;
    }

    Ok(())
}

fn read(last: u64) -> Result<(), BoxError> {
    let mut hash_vec = Vec::new();
    let mut vec_from_zero = Vec::new();

    if last > 1 {
        println!("blocks check started");
        for i in 2..=last {
            println!("i >> {}", i);
            let fname = create_file_name(i);
            let bytes = get_file_bytes(&fname)?;
            let block = Block::deserialize(bytes).unwrap();

            let v = get_file_bytes(&create_file_name(i - 1))?;
            hash_vec.push(new_hash(str::from_utf8(&v)?));

            let idx = i as usize;
            if block.hash == hash_vec[idx - 2] {
                println!("[BLOCK]: {}] -> OK", idx - 1)
            } else {
                println!("[BLOCK]: {}] -> CORRUPTED", idx - 1)
            }
        }
    };
    println!("blocks check done");

    let v = get_file_bytes(&create_file_name(last))?;
    hash_vec.push(new_hash(str::from_utf8(&v)?));

    // from zero block
    println!("blocks check from zero started");
    let v = get_file_bytes(&create_file_name(0))?;
    let s = String::from_utf8(v)?;

    let split: Vec<&str> = s.lines().collect();

    for line in split {
        vec_from_zero.push(line.to_owned());
    }

    for i in 0..last {
        let idx = i as usize;
        if vec_from_zero[idx] == hash_vec[idx] {
            println!("[BLOCK]: {}] -> OK", idx + 1)
        } else {
            println!("[BLOCK]: {}] -> CORRUPTED", idx + 1)
        }
    }

    println!("blocks check from zero done");

    Ok(())
}

fn write(last: u64, from: String, to: String, sum: u64) -> Result<(), BoxError> {
    let new = create_file_name(last + 1);
    let mut hash = "".to_owned();

    if Path::new(&new).exists() {
        fs::remove_file(&new)?;
    };

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(&new)?;

    if last > 0 {
        let fname = create_file_name(last);
        let bytes = get_file_bytes(&fname)?;
        hash = new_hash(str::from_utf8(&bytes)?)
    }

    let block = Block::new(from, to, sum, hash);
    let s = block.serialize()?;
    let _ = file.write(&s.as_bytes().to_vec())?;

    let bytes = get_file_bytes(&new)?;

    zero_block(&new_hash(str::from_utf8(&bytes)?))?;
    Ok(())
}

#[test]
fn test_write() {
    match write(2, "Den".to_owned(), "Nis".to_owned(), 228) {
        Ok(()) => println!("done"),
        Err(err) => exit_with_err(err),
    }
}

fn zero_block(hash: &str) -> Result<(), BoxError> {
    let zero = create_file_name(0);

    if !Path::new(&zero).exists() {
        File::create(&zero)?;
    };

    let mut file = OpenOptions::new().write(true).append(true).open(&zero)?;

    let mut new_hash = hash.to_owned();

    new_hash.push('\n');

    let _ = file.write(&new_hash.as_bytes().to_vec())?;

    Ok(())
}

fn last_block(dir: &str) -> Result<u64, BoxError> {
    let paths = fs::read_dir(dir)?;
    let mut max: u64 = 0;
    for path in paths {
        let pb = path?;
        let path = pb.path();
        match path.extension() {
            Some(p) if p == "json" => {
                let path_str = path.file_name().unwrap();
                let s = path_str.to_str().unwrap();
                let splits: Vec<&str> = s.split('.').collect();
                let possible_max: u64 = splits[0].parse().unwrap();
                if possible_max > max {
                    max = possible_max
                }
            }
            _ => (),
        }
    }
    Ok(max)
}

#[test]
fn test_last_block() {
    if let Ok(max) = last_block(DIR) {
        assert_eq!(max, 1_i64);
    };
}

fn get_file_bytes(filename: &str) -> Result<Vec<u8>, BoxError> {
    let mut file = fs::File::open(filename)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

#[test]
fn test_get_file_bytes() {
    if let Ok(buf) = get_file_bytes("./testdata/1.json") {
        let s = match str::from_utf8(&buf) {
            Ok(v) => {
                println!("{}", v);
                assert_eq!(v, "test_get_file_bytes");
            }
            Err(e) => panic!("invalid utf-8 sequence: {}", e),
        };
    };
}

fn new_hash(msg: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes().to_vec());
    let res = hasher.finalize();
    hex::encode(res)
}

#[test]
fn test_new_hash() {
    let s = new_hash("message");
    assert_eq!(
        s,
        "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d"
    );
}

fn create_file_name(idx: u64) -> String {
    let mut fname: String = "".to_string();
    fname.push_str(DIR);
    fname.push('/');
    fname.push_str(&idx.to_string());
    fname.push_str(EXTENSION);
    fname
}

#[test]
fn test_create_file_name() {
    let path = create_file_name(222);
    assert_eq!(path, "data/222.json")
}

impl Block {
    fn new(from: String, to: String, sum: u64, hash: String) -> Self {
        Block {
            from,
            to,
            sum,
            hash,
        }
    }

    fn deserialize(bytes: Vec<u8>) -> Option<Self> {
        match serde_json::from_slice::<Self>(&bytes) {
            Ok(data) => return Some(data),
            Err(_) => return None,
        };
    }

    fn serialize(&self) -> Result<String, BoxError> {
        let res = serde_json::to_string_pretty(&self)?;
        Ok(res)
    }
}

#[test]
fn test_block_serialize() {
    let block = Block::new("Den".to_owned(), "Nis".to_owned(), 228, "".to_owned());
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

    if let Some(block) = Block::deserialize(s.as_bytes().to_vec()) {
        assert_eq!(block.from, "Den");
        assert_eq!(block.to, "Nis");
        assert_eq!(block.sum, 228);
        assert_eq!(block.hash, "");
        println!("{:?}", block);
    };
}

fn exit_with_err(err: BoxError) {
    eprintln!("error: {}", err);
    let mut source = err.source();
    while let Some(err) = source {
        eprintln!(" because {}", err);
        source = err.source();
    }
    std::process::exit(1);
}
