//! THIS CRATE HAS NOT UNDERGONE AUDITS AND SHOULD NOT BE USED FOR SECURE PURPOSES BUT ONLY FOR EDUCATIONAL AND SCIENTIFIC PURPOSES
//!
//! ### KEM generation
//! ```rust
//! use pqc_kyber::*;
//! use kyberauth::*;
//! use std::net::SocketAddr;
//! fn createkeys() -> Result<Keypair, KyberError> {
//!     let mut rng = rand::thread_rng();
//!     keypair(&mut rng)
//! }
//! ```
//! ### Server and client interface
//!
//! #### Client
//!
//! ```rust
//! use pqc_kyber::*;
//! use std::net::{IpAddr,SocketAddr,Ipv4Addr};
//! use kyberauth::*;
//! const TEST: &str="HELLO WORLD";
//! async fn server() -> Result<(), KyberError> {
//!     let mut rng = rand::thread_rng();
//!     let keys = keypair(&mut rng)?;
//!     let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
//!     let listener = server::startlistener(addr).await;
//!     let listener = match listener {
//!         Ok(listener) => listener,
//!         Err(_) => {
//!             return Err(KyberError::InvalidInput);
//!         }
//!     };
//!     let _ = match server::listener(&keys, listener, false).await {
//!         Ok(mut elem) => {
//!             elem.senddata(TEST.as_bytes()).await.unwrap();
//!             return Ok(());
//!         }
//!         Err(e) => {
//!             return Err(KyberError::InvalidInput);
//!         }
//!     };
//! }
//! ```
//! #### Server
//!
//! ```rust
//! use pqc_kyber::*;
//! use std::net::{Ipv4Addr,SocketAddr,IpAddr};
//! use kyberauth::client;
//! const TEST: &str="HELLO WORLD";
//! async fn client() -> Result<(), KyberError> {
//!     let mut rng = rand::thread_rng();
//!     let keys = keypair(&mut rng)?;
//!     let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
//!     let _ = match client::connecter(&keys, addr).await {
//!         Ok(mut elem) => {
//!             let text = elem.receivedata().await.unwrap();
//!             if text.len() == 0 {
//!                 eprintln!("Invalid response!");
//!                 return Err(KyberError::InvalidInput);
//!             }
//!             let info = String::from_utf8(text).unwrap();
//!             assert_eq!(info, TEST);
//!             println!("The peer is {} and public key is {}",elem.getpeer(),String::from_utf8(elem.getpeerkey(false).unwrap()).unwrap());
//!             ()
//!         }
//!         Err(e) => {
//!             eprintln!("Error is {}", e);
//!             return Err(KyberError::InvalidInput);
//!         }
//!     };
//!     Ok(())
//! }
//! ```
use hex;
pub mod aes;
pub mod client;
pub mod key;
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
use tempfile::tempfile;
const PRIVATEKEY: &str = "privatekey.srt";
const PUBLICKEY: &str = "publickey.pub";
#[cfg(windows)]
const LINE_ENDING: &'static str = "\r\n";
#[cfg(not(windows))]
const LINE_ENDING: &'static str = "\n";
fn createfile(file: &Path, secure: bool) -> Result<File, Error> {
    #[cfg(target_family = "windows")]
    #[allow(unreachable_code)]
    {
        return fs::OpenOptions::new()
            .create(true)
            .attributes(winapi::FILE_ATTRIBUTE_READONLY)
            .write(true)
            .open(&file);
    }
    #[cfg(target_family = "unix")]
    #[allow(unreachable_code)]
    {
        let umode: u32 = if secure { 0o600 } else { 0o644 };
        return fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(umode)
            .open(&file);
    }
    #[allow(unreachable_code)]
    fs::OpenOptions::new().create(true).write(true).open(&file)
}
/// Print private key and public key to a file. Keep your private key safe.
/// Keys is the keypair, privatekey is the first to write the private key and publickey the file to create public key.
/// Ex:
/// ```rust
/// use pqc_kyber::*;
/// use kyberauth::*;
/// use std::fs;
/// let mut rng = rand::thread_rng();
/// let mut keys = keypair(&mut rng).unwrap();
/// let _ = printkeystofile(&keys,Some("/tmp/test_privatekey.srt"),Some("/tmp/test_publickey.srt")).unwrap();
/// ```
pub fn printkeystofile(
    keys: &Keypair,
    privatekey: Option<&str>,
    publickey: Option<&str>,
) -> std::io::Result<()> {
    let privatefile = privatekey.unwrap_or(PRIVATEKEY);
    let publicfile = publickey.unwrap_or(PUBLICKEY);
    let temp = privatefile.contains("test");
    let mut file;
    if temp {
        file = tempfile()?;
    } else {
        file = createfile(Path::new(privatefile), true)?;
    }
    let mut text = getkeyheader(true, true);
    text.push_str(LINE_ENDING);
    text.push_str(&hex::encode(&keys.secret));
    text.push_str(LINE_ENDING);
    text.push_str(&getkeyheader(true, false));
    file.write_all(text.as_bytes())?;
    file = createfile(Path::new(publicfile), false)?;
    let mut text = getkeyheader(false, true);
    text.push_str(LINE_ENDING);
    text.push_str(&hex::encode(&keys.public));
    text.push_str(LINE_ENDING);
    text.push_str(&getkeyheader(false, false));
    file.write_all(text.as_bytes())?;
    Ok(())
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
/// Extract keys from public or private file containing the key
/// ```rust
/// use pqc_kyber::*;
/// use kyberauth::*;
/// use std::fs;
/// let mut rng = rand::thread_rng();
/// let mut keys = keypair(&mut rng).unwrap();
/// let _ = printkeystofile(&keys,Some("/tmp/privatekey2.srt"),Some("/tmp/publickey2.srt")).unwrap();
/// let publickeystring = checkandextractkeys(&fs::read_to_string("/tmp/privatekey2.srt").unwrap(),true);
/// let _ = fs::remove_file("/tmp/privatekey2.srt");
/// let _ = fs::remove_file("/tmp/publickey2.srt");
/// ```
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
