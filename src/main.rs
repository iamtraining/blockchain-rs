#![allow(dead_code, unused_variables, unused_imports)]
use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::{File, OpenOptions};

use std::convert;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::usize;

const DIR: &str = "./data";
const READ: &str = "read";
const WRITE: &str = "write";
const EXTENSION: &str = ".json";

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
        write(last, "Den", "Nis", 228)?;
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
            let fname = format_block_file_name(i);
            let bytes = fs::read(&fname)?;
            let block: Block = serde_json::from_slice(&bytes)?;

            let v = fs::read(&format_block_file_name(i - 1))?;
            hash_vec.push(new_hash(std::str::from_utf8(&v)?));

            let idx = i as usize;
            if block.hash == hash_vec[idx - 2] {
                println!("[BLOCK]: {}] -> OK", idx - 1)
            } else {
                println!("[BLOCK]: {}] -> CORRUPTED", idx - 1)
            }
        }
    };
    println!("blocks check done");

    let v = fs::read(&format_block_file_name(last))?;
    hash_vec.push(new_hash(std::str::from_utf8(&v)?));

    // from zero block
    println!("blocks check from zero started");
    let v = fs::read(&format_block_file_name(0))?;
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

fn write(last: u64, from: &str, to: &str, sum: u64) -> Result<(), BoxError> {
    let new = format_block_file_name(last + 1);
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
        let fname = format_block_file_name(last);
        let bytes = fs::read(&fname)?;
        hash = new_hash(std::str::from_utf8(&bytes)?)
    }

    let block = Block::new(from, to, sum, hash);
    let json = serde_json::to_vec_pretty(&block)?;
    let _ = file.write(&json)?;

    let bytes = fs::read(&new)?;

    zero_block(&new_hash(std::str::from_utf8(&bytes)?))?;
    Ok(())
}

fn zero_block(hash: &str) -> Result<(), BoxError> {
    let zero = format_block_file_name(0);

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

fn new_hash(msg: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes().to_vec());
    let res = hasher.finalize();
    hex::encode(res)
}

fn format_block_file_name(idx: u64) -> PathBuf {
    let mut buf = itoa::Buffer::new();
    let idx = buf.format(idx);

    let mut path = PathBuf::with_capacity(DIR.len() + 1 + idx.len() + EXTENSION.len());

    path.push(DIR);
    path.push(idx);
    path.set_extension(EXTENSION);

    path
}

impl Block {
    fn new(from: impl Into<String>, to: impl Into<String>, sum: u64, hash: String) -> Self {
        Block {
            from: from.into(),
            to: to.into(),
            sum,
            hash,
        }
    }
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

#[cfg(test)]
mod tests;
