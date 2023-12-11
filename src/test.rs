#[cfg(test)]
mod tests {
    use hex;
    use pqc_dilithium as signing;
    use pqc_kyber::*;
    use rand::{self, Fill};
    use std::convert::TryInto;
    use std::fs::{self, File};
    use std::io::Error;
    use std::io::{ErrorKind, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::{Path, PathBuf};
    extern crate winapi;
    #[cfg(target_family = "unix")]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    #[cfg(target_family = "windows")]
    use std::os::windows::fs::OpenOptionsExt;
    #[cfg(target_family = "windows")]
    use std::os::windows::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::server::startlistener;
    const PRIVATEKEY_TEST: &str = "test_privatekey.srt";
    const PUBLICKEY_TEST: &str = "test_publickey.pub";
    #[cfg(windows)]
    const LINE_ENDING: &'static str = "\r\n";
    #[cfg(not(windows))]
    const LINE_ENDING: &'static str = "\n";
    const TEST: &str = "HELLO WORLD";
    async fn server() -> Result<(), KyberError> {
        let mut rng = rand::thread_rng();
        let keys = keypair(&mut rng)?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
        let listener = crate::server::startlistener(addr).await;
        let listener = match listener {
            Ok(listener) => listener,
            Err(_) => {
                return Err(KyberError::InvalidInput);
            }
        };
        let _ = match crate::server::listener(&keys, listener,true).await {
            Ok(mut elem) => {
                elem.senddata(TEST.as_bytes()).await.unwrap();
                return Ok(());
            }
            Err(e) => {
                return Err(KyberError::InvalidInput);
            }
        };
    }
    async fn client() -> Result<(), KyberError> {
        let mut rng = rand::thread_rng();
        let keys = keypair(&mut rng)?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
        let _ = match crate::client::connecter(&keys, addr).await {
            Ok(mut elem) => {
                let text = elem.receivedata().await.unwrap();
                if text.len() == 0 {
                    eprintln!("Invalid response!");
                    return Err(KyberError::InvalidInput);
                }
                let info = String::from_utf8(text).unwrap();
                assert_eq!(info, TEST);
                ()
            }
            Err(e) => {
                eprintln!("Error is {}", e);
                return Err(KyberError::InvalidInput);
            }
        };
        Ok(())
    }
    #[test]
    fn checkinputkeys() -> Result<(), KyberError> {
        let mut rng = rand::thread_rng();
        let mut keys = keypair(&mut rng)?;
        crate::printkeystofile(&keys, Some(PRIVATEKEY_TEST), Some(PUBLICKEY_TEST));
        let public = fs::read(PUBLICKEY_TEST).expect("Cannot read keys.");
        let secret = fs::read(PRIVATEKEY_TEST).expect("Cannot read keys.");
        let public = String::from_utf8(public).expect("Invalid key");
        let public = crate::checkandextractkeys(&public, false).expect("Invalid key");
        let public = hex::decode(public).expect("Invalid key");
        let mut public: [u8; KYBER_PUBLICKEYBYTES] = public[..KYBER_PUBLICKEYBYTES]
            .try_into()
            .expect("Invalid key");
        let secret = String::from_utf8(secret).expect("Invalid key");
        let secret = crate::checkandextractkeys(&secret, true).expect("Invalid key");
        let secret = hex::decode(secret).expect("Invalid key");
        let mut secret: [u8; KYBER_SECRETKEYBYTES] = secret[..KYBER_SECRETKEYBYTES]
            .try_into()
            .expect("Invalid key");
        keys = crate::key::keypairfrom(&mut public, &mut secret, &mut rng)?;
        let _ = fs::remove_file(PRIVATEKEY_TEST);
        let _ = fs::remove_file(PUBLICKEY_TEST);
        Ok(())
    }
    #[tokio::test]
    async fn testpeer() -> Result<(), KyberError> {
        //TODO: Execute both at the same time
        server().await?;
        client().await?;
        Ok(())

    }
}
