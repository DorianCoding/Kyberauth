use hex;
pub mod client;
pub mod key;
pub mod aes;
pub mod server;
use pqc_kyber::*;
use std::io::Error;
use std::path::Path;
extern crate winapi;
use std::fs::{self, File};
use std::io::{ErrorKind, Write};
#[cfg(target_family = "unix")]
use std::os::unix::fs::OpenOptionsExt;
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
        let umode: u32 = if secure { 0o400 } else { 0o444 };
        return fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(umode)
            .open(&file);
    }
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&file)
}
pub fn printkeystofile(keys: &Keypair, privatekey: Option<&str>, publickey: Option<&str>) {
    let privatefile = privatekey.unwrap_or(PRIVATEKEY);
    let publicfile = publickey.unwrap_or(PUBLICKEY);
    let mut file = createfile(Path::new(privatefile), true).expect("Cannot create file");
    let mut text = getkeyheader(true, true);
    text.push_str(LINE_ENDING);
    text.push_str(&hex::encode(&keys.secret));
    text.push_str(LINE_ENDING);
    text.push_str(&getkeyheader(true, false));
    file.write_all(text.as_bytes())
        .expect("Invalid writing key");
    file = createfile(Path::new(publicfile), false).expect("Cannot create file");
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
pub fn checkandextractkeys(key: &str, private: bool) -> Result<String, ErrorKind> {
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