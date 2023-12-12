#[cfg(test)]
mod tests {
    use hex;
    use pqc_kyber::*;
    use rand;
    use kyberauth::*;
    use tokio::task::JoinSet;
    use std::convert::TryInto;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    extern crate winapi;
    const PRIVATEKEY_TEST: &str = "test_privatekey.srt";
    const PUBLICKEY_TEST: &str = "test_publickey.pub";
    const TEST: &str = "HELLO WORLD";
    async fn server() -> Result<(), KyberError> {
        let mut rng = rand::thread_rng();
        let keys = keypair(&mut rng)?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
        let listener = server::startlistener(addr).await;
        let listener = match listener {
            Ok(listener) => listener,
            Err(_) => {
                return Err(KyberError::InvalidInput);
            }
        };
        let _ = match server::listener(&keys, listener, false).await {
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
        let _ = match client::connecter(&keys, addr).await {
            Ok(mut elem) => {
                let text = elem.receivedata().await.unwrap();
                if text.len() == 0 {
                    eprintln!("Invalid response!");
                    return Err(KyberError::InvalidInput);
                }
                let info = String::from_utf8(text).unwrap();
                assert_eq!(info, TEST);
                println!("The peer is {} and public key is {}",elem.getpeer(),String::from_utf8(elem.getpeerkey(false).unwrap()).unwrap());
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
        kyberauth::printkeystofile(&keys, Some(PRIVATEKEY_TEST), Some(PUBLICKEY_TEST));
        let public = fs::read(PUBLICKEY_TEST).expect("Cannot read keys.");
        let secret = fs::read(PRIVATEKEY_TEST).expect("Cannot read keys.");
        let public = String::from_utf8(public).expect("Invalid key");
        let public = kyberauth::checkandextractkeys(&public, false).expect("Invalid key");
        let public = hex::decode(public).expect("Invalid key");
        let mut public: [u8; KYBER_PUBLICKEYBYTES] = public[..KYBER_PUBLICKEYBYTES]
            .try_into()
            .expect("Invalid key");
        let secret = String::from_utf8(secret).expect("Invalid key");
        let secret = kyberauth::checkandextractkeys(&secret, true).expect("Invalid key");
        let secret = hex::decode(secret).expect("Invalid key");
        let mut secret: [u8; KYBER_SECRETKEYBYTES] = secret[..KYBER_SECRETKEYBYTES]
            .try_into()
            .expect("Invalid key");
        keys = kyberauth::key::keypairfrom(&mut public, &mut secret, &mut rng)?;
        let _ = fs::remove_file(PRIVATEKEY_TEST);
        let _ = fs::remove_file(PUBLICKEY_TEST);
        Ok(())
    }
    #[tokio::test]
    async fn testpeer() -> Result<(), KyberError> {
        let mut set = JoinSet::new();
        set.spawn(async {
            let _ = server();
            return;
        });
        set.spawn(async {
            let _ = client();
            return;
        });
        loop {
            let result = set.join_next().await;
            match result {
                Some(data) => {
                    match data {
                        Ok(_) => continue,
                        Err(e) => {
                            panic!("Error is {}",e);
                        }
                    }
                },
                None => {
                    break;
                }
            }
        }
        Ok(())

    }
}
