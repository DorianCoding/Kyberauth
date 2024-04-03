#[cfg(test)]
mod tests {
    use hex;
    use kyberauth::*;
    use pqc_kyber::*;
    use rand;
    use futures::future;
    use std::convert::TryInto;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::fs;
    //use tokio::task::JoinSet;
    extern crate winapi;
    const PRIVATEKEY_TEST: &str = "tes_privatekey.srt";
    const PUBLICKEY_TEST: &str = "tes_publickey.pub";
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
        println!("Listening in process");
        let _ = match server::listener(&keys, listener, true).await {
            Ok(mut elem) => {
                println!("Data sent!");
                elem.senddata(TEST.as_bytes()).await.unwrap();
                return Ok(());
            }
            Err(e) => {
                eprintln!("Error listening {:?}", e);
                return Err(KyberError::InvalidInput);
            }
        };
    }
    async fn client() -> Result<(), KyberError> {
        let mut rng = rand::thread_rng();
        let keys = keypair(&mut rng)?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
        println!("Wairing!");
        let _ = match client::connecter(&keys, addr).await {
            Ok(mut elem) => {
                eprintln!("Connection done!");
                let text = elem.receivedata().await.unwrap();
                if text.len() == 0 {
                    eprintln!("Invalid response!");
                    return Err(KyberError::InvalidInput);
                }
                let info = String::from_utf8(text).unwrap();
                assert_eq!(info, TEST);
                println!(
                    "The peer is {} and public key is {}",
                    elem.getpeer(),
                    String::from_utf8(elem.getpeerkey(true).unwrap()).unwrap()
                );
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
        let keys = keypair(&mut rng)?;
        kyberauth::printkeystofile(&keys, Some(PRIVATEKEY_TEST), Some(PUBLICKEY_TEST)).unwrap();
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
        let keys2 = kyberauth::key::keypairfrom(&mut public, &mut secret, &mut rng)?;
        assert_eq!(keys,keys2);
        let _ = fs::remove_file(PRIVATEKEY_TEST);
        let _ = fs::remove_file(PUBLICKEY_TEST);
        Ok(())
    }
    #[tokio::test]
    async fn testpeer() -> Result<(), KyberError> {
        let (s, g) = future::join(server(), client()).await;
        if s.is_err() || g.is_err() {
            panic!("Invalid result");
        }
        Ok(())
    }
}
