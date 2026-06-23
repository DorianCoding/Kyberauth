//! THIS CRATE HAS NOT UNDERGONE AUDITS AND SHOULD NOT BE USED FOR SECURE PURPOSES BUT ONLY FOR EDUCATIONAL AND SCIENTIFIC PURPOSES
//! THIS CRATE USES SAFE_PQC_KYBER BECAUSE OF https://github.com/rustsec/advisory-db/pull/1872/files
//! ### KEM generation
//! ```rust
//! use safe_pqc_kyber::*;
//! use kyberauth::*;
//! use std::net::SocketAddr;
//! #[cfg(feature = "rand")]
//! fn createkeys() -> Keypair {
//!     let mut rng = rand_core::OsRng::default();
//!     keypair(&mut rng)
//! }
//! ```
//! ### Server and client interface
//!
//! #### Server
//!
//! ```rust
//! use safe_pqc_kyber::*;
//! use std::net::{IpAddr,SocketAddr,Ipv4Addr};
//! use kyberauth::*;
//! const TEST: &str="HELLO WORLD";
//! #[cfg(feature = "server")]
//! async fn server() -> Result<(), KyberError> {
//!     let mut rng = rand_core::OsRng::default();
//!     let keys = keypair(&mut rng);
//!     let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
//!     let listener = server::startlistener(addr).await;
//!     let listener = match listener {
//!         Ok(listener) => listener,
//!         Err(_) => {
//!             return Err(KyberError::InvalidInput);
//!         }
//!     };
//! match listener.accept().await.map(|f| f.accept()) {
//! Some(Ok(d)) => {
//! let d = d.await.map_err(|_| KyberError::InvalidInput)?;
//! match server::listener(&keys, d, false).await {
//! Ok((_, mut elem)) => {
//! elem.senddata(TEST.as_bytes()).await.unwrap();
//! return Ok(());}
//!            Err(e) => {
//!                eprintln!("Error listening {:?}", e);
//!                return Err(KyberError::InvalidInput);
//!            }
//!        }
//!    }
//!    _ => return Err(KyberError::InvalidInput)
//! }
//! }
//! ```
//! #### Client
//!
//! ```rust
//! use safe_pqc_kyber::*;
//! use std::net::{Ipv4Addr,SocketAddr,IpAddr};
//! use kyberauth::*;
//! const TEST: &str="HELLO WORLD";
//! #[cfg(feature = "client")]
//! async fn client() -> Result<(), KyberError> {
//!     let mut rng = rand_core::OsRng::default();
//!     let keys = keypair(&mut rng);
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
// Implementation of `ServerCertVerifier` that verifies everything as trustworthy.
#[warn(clippy::unwrap_used)]
#[warn(clippy::expect_used)]
#[derive(Debug)]
#[cfg(feature = "client")]
struct SkipServerVerification(Arc<CryptoProvider>);
#[cfg(feature = "client")]
impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}
#[cfg(feature = "client")]
impl danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<danger::ServerCertVerified, rustls::Error> {
        Ok(danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
#[cfg(feature = "aes")]
pub mod aes;
#[cfg(feature = "client")]
pub mod client;
pub mod key;
#[cfg(feature = "server")]
pub mod server;
pub mod r#struct;
#[cfg(feature = "client")]
use rustls::client::danger;
#[cfg(feature = "client")]
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
#[cfg(feature = "client")]
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
#[cfg(feature = "client")]
use rustls::{DigitallySignedStruct, SignatureScheme};
use safe_pqc_kyber::*;
use std::path::Path;
extern crate winapi;
use std::io::{self, ErrorKind, Write};
#[cfg(feature = "client")]
use std::sync::Arc;

use crate::r#struct::SecureFile;
const PRIVATEKEY: &str = "privatekey.srt";
const PUBLICKEY: &str = "publickey.pub";
#[cfg(windows)]
const LINE_ENDING: &str = "\r\n";
#[cfg(not(windows))]
const LINE_ENDING: &str = "\n";
/// Print private key and public key to a file. Keep your private key safe.
/// Keys is the keypair, privatekey is the first to write the private key and publickey the file to create public key.
/// # Examples
/// ```rust
/// #[cfg(feature = "rand")]
/// {
/// use safe_pqc_kyber::*;
/// use kyberauth::*;
/// use std::fs;
/// let mut rng = rand_core::OsRng::default();
/// let mut keys = keypair(&mut rng);
/// let _ = printkeystofile(&keys,Some("/tmp/test_privatekey.srt"),Some("/tmp/test_publickey.srt")).unwrap();
/// let _ = fs::remove_file("/tmp/test_privatekey.srt");
/// let _ = fs::remove_file("/tmp/test_publickey.srt");
/// }
/// ```
pub fn printkeystofile<T>(
    keys: &Keypair,
    privatekey: Option<T>,
    publickey: Option<T>,
) -> std::io::Result<()>
where
    T: AsRef<str>,
{
    let privatefile = match privatekey {
        Some(p) => String::from(p.as_ref()),
        None => String::from(PRIVATEKEY),
    };
    let publicfile = match publickey {
        Some(p) => String::from(p.as_ref()),
        None => String::from(PUBLICKEY),
    };
    let mut file = SecureFile::createfrompath(Path::new(&privatefile), true, false)?;
    let mut text = getkeyheader(true, true);
    text.push_str(LINE_ENDING);
    text.push_str(&hex::encode(keys.secret));
    text.push_str(LINE_ENDING);
    text.push_str(&getkeyheader(true, false));
    file.getmutfile().write_all(text.as_bytes())?;
    file = SecureFile::createfrompath(Path::new(&publicfile), false, false)?;
    let mut text = getkeyheader(false, true);
    text.push_str(LINE_ENDING);
    text.push_str(&hex::encode(keys.public));
    text.push_str(LINE_ENDING);
    text.push_str(&getkeyheader(false, false));
    file.getmutfile().write_all(text.as_bytes())?;
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
/// #[cfg(feature="rand")]
/// {
/// use safe_pqc_kyber::*;
/// use kyberauth::*;
/// use std::fs;
/// let mut rng = rand_core::OsRng::default();
/// let mut keys = keypair(&mut rng);
/// let _ = printkeystofile(&keys,Some("/tmp/privatekey2.srt"),Some("/tmp/publickey2.srt")).unwrap();
/// let publickeystring = checkandextractkeys(&fs::read_to_string("/tmp/privatekey2.srt").unwrap(),true);
/// let _ = fs::remove_file("/tmp/privatekey2.srt");
/// let _ = fs::remove_file("/tmp/publickey2.srt");
/// }
/// ```
pub fn checkandextractkeys<T>(key: T, private: bool) -> io::Result<String>
where
    T: AsRef<str>,
{
    let key = key.as_ref();
    let element: Vec<&str> = key.split(LINE_ENDING).collect();
    if element.len() != 3 {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    if element[0].trim() != getkeyheader(private, true)
        || element[2].trim() != getkeyheader(private, false)
    {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    return Ok(String::from(element[1].trim()));
}
