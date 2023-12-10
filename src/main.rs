use std::io::Error;
use std::path::{Path, PathBuf};
extern crate winapi;
use clap::Parser;
use hex;
mod client;
mod key;
mod aes;
use aes::Connection;
mod server;
use pqc_dilithium as signing;
use pqc_kyber::*;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use rand::{self, Fill};
use std::convert::TryInto;
use std::fs::{self, File};
use std::io::{ErrorKind, Write};
#[cfg(target_family = "unix")]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(target_family = "windows")]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(target_family = "windows")]
use std::os::windows::prelude::*;
const PRIVATEKEY: &str = "privatekey.srt";
const PUBLICKEY: &str = "publickey.pub";
#[cfg(windows)]
const LINE_ENDING: &'static str = "\r\n";
#[cfg(not(windows))]
const LINE_ENDING: &'static str = "\n";
/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Generate new keys
    #[arg(short, long)]
    create: bool,
    /// File to send
    #[arg(short, long)]
    input: PathBuf,
    /// Listening to connection
    #[arg(short, long)]
    server: bool,
}
#[allow(unreachable_code)]
fn createfile(file: &Path, secure: bool) -> Result<File, Error> {
    #[cfg(target_family = "windows")]
    {
        return fs::OpenOptions::new()
            .create(true)
            .attributes(winapi::FILE_ATTRIBUTE_READONLY)
            .write(true)
            .open(&file);
    }
    #[cfg(target_family = "unix")]
    {
        let umode: u32 = if secure { 0o600 } else { 0o644 };
        return fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(umode)
            .open(&file);
    }
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o770)
        .open(&file)
}
fn printkeystofile(keys: &Keypair) {
    let mut file = createfile(Path::new(PRIVATEKEY), true).expect("Cannot create file");
    let mut text = getkeyheader(true, true);
    text.push_str(LINE_ENDING);
    text.push_str(&hex::encode(&keys.secret));
    text.push_str(LINE_ENDING);
    text.push_str(&getkeyheader(true, false));
    file.write_all(text.as_bytes())
        .expect("Invalid writing key");
    file = createfile(Path::new(PUBLICKEY), false).expect("Cannot create file");
    let mut text = getkeyheader(false, true);
    text.push_str(LINE_ENDING);
    text.push_str(&hex::encode(&keys.public));
    text.push_str(LINE_ENDING);
    text.push_str(&getkeyheader(false, false));
    file.write_all(text.as_bytes())
        .expect("Invalid writing key");
}
fn getkeyheader(private: bool, start: bool) -> String {
    match private {
        true => match start {
            true => String::from("-----BEGIN KYBER PRIVATE KEY-----"),
            false => String::from("-----END KYBER PRIVATE KEY-----"),
        },
        false => match start {
            true => String::from("-----BEGIN KYBER PUBLIC KEY-----"),
            false => String::from("-----END KYBER PUBLIC KEY-----"),
        },
    }
}
fn checkandextractkeys(key: &str, private: bool) -> Result<String, ErrorKind> {
    let element: Vec<&str> = key.split(LINE_ENDING).collect();
    if element.len() != 3 {
        return Err(ErrorKind::InvalidInput);
    }
    if element[0].trim() != getkeyheader(private, true) {
        return Err(ErrorKind::InvalidData);
    } else if element[2].trim() != getkeyheader(private, false) {
        return Err(ErrorKind::InvalidData);
    }
    return Ok(String::from(element[1].trim()));
}
#[tokio::main]
async fn main() -> Result<(), KyberError> {
    let args = Args::parse();
    let mut rng = rand::thread_rng();
    let mut keys = keypair(&mut rng)?;
    if args.create {
        printkeystofile(&keys);
    } else {
        let public = fs::read(PUBLICKEY).expect("Cannot read keys.");
        let secret = fs::read(PRIVATEKEY).expect("Cannot read keys.");
        let public = String::from_utf8(public).expect("Invalid key");
        let public = checkandextractkeys(&public, false).expect("Invalid key");
        let public = hex::decode(public).expect("Invalid key");
        let mut public: [u8; KYBER_PUBLICKEYBYTES] = public[..KYBER_PUBLICKEYBYTES]
            .try_into()
            .expect("Invalid key");
        let secret = String::from_utf8(secret).expect("Invalid key");
        let secret = checkandextractkeys(&secret, true).expect("Invalid key");
        let secret = hex::decode(secret).expect("Invalid key");
        let mut secret: [u8; KYBER_SECRETKEYBYTES] = secret[..KYBER_SECRETKEYBYTES]
            .try_into()
            .expect("Invalid key");
        keys = key::keypairfrom(&mut public, &mut secret, &mut rng)?;
    }
    if args.server {
        loop {
            let _ = match server::listener(&keys).await {
                Ok(mut elem) => {
                    println!("Peer is : {}",elem.peer_addr);
                    let text="Hello world!";
                    elem.senddata(text.as_bytes()).await.unwrap();
                    continue;
                },
                Err(e) => {
                    eprintln!("Error is {}", e);
                    return Ok(());
                }
            };
        }
    } else {
        let _ = match client::connecter(&keys).await {
            Ok(mut elem) => {
                println!("Peer is : {}",elem.peer_addr);
                let text = elem.receivedata().await.unwrap();
                if text.len() == 0 {
                    eprintln!("Invalid response!");
                    return Ok(());
                }
                println!("Result: {}",String::from_utf8(text).unwrap());
            },
            Err(e) => {
                eprintln!("Error is {}", e);
                return Ok(());
            }
        };
    }
    Ok(())
}
