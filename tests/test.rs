#[cfg(test)]
mod tests {
    #[cfg(feature = "server")]
    use kyberauth::server;
    use safe_pqc_kyber::*;
    use std::convert::TryInto;
    use std::fs;
    #[cfg(feature = "server")]
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };
    //use tokio::task::JoinSet;
    extern crate winapi;
    const PRIVATEKEY_TEST: &str = "tes_privatekey.srt";
    const PUBLICKEY_TEST: &str = "tes_publickey.pub";
    const TEST: &str = "HELLO WORLD";
    #[cfg(feature = "server")]
    async fn servergen(keys: &Keypair, addr: SocketAddr) -> Result<(), KyberError> {
        let listener = server::startlistener(addr).await;
        let listener = match listener {
            Ok(listener) => listener,
            Err(_) => {
                return Err(KyberError::InvalidInput);
            }
        };
        loop {
            match listener.accept().await.map(|f| f.accept()) {
                Some(Ok(d)) => {
                    println!("Got a connection from {}", d.remote_address());
                    let d = d.await.map_err(|_| KyberError::InvalidInput)?;
                    println!("ID is {}", d.stable_id());
                    match server::listener(&keys, d, false).await {
                        Ok((_, mut elem)) => {
                            elem.senddata(TEST.as_bytes()).await.unwrap();
                            return Ok(());
                        }
                        Err(e) => {
                            eprintln!("Error listening {:?}", e);
                            return Err(KyberError::InvalidInput);
                        }
                    }
                }
                _ => break,
            }
        }
        return Err(KyberError::InvalidInput);
    }
    #[cfg(feature = "server")]
    async fn server() -> Result<(), KyberError> {
        let mut rng = rand_core::OsRng::default();
        let keys = keypair(&mut rng);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
        if let Err(_) = tokio::time::timeout(Duration::new(10, 0), servergen(&keys, addr)).await {
            panic!("Timeout connection");
        }
        Ok(())
    }
    #[cfg(feature = "client")]
    async fn clientgen(keys: &Keypair, addr: SocketAddr) -> Result<(), KyberError> {
        use kyberauth::client;

        match client::connecter(&keys, addr).await {
            Ok(mut elem) => {
                let text = elem.receivedata().await.unwrap();
                if text.is_empty() {
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
            }
            Err(e) => {
                eprintln!("Error is {}", e);
                return Err(KyberError::InvalidInput);
            }
        };
        Ok(())
    }
    #[cfg(feature = "client")]
    async fn client() -> Result<(), KyberError> {
        use sha3::{Digest, Sha3_256};

        let mut rng = rand_core::OsRng::default();
        let keys = keypair(&mut rng);
        // create a SHA3-256 object
        let mut hasher = Sha3_256::new();

        // write input message
        hasher.update(keys.public);

        // read hash digest
        let result = hex::encode(hasher.finalize());
        fs::write("authorized_keys", result).unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
        println!("Wairing!");
        if let Err(_) = tokio::time::timeout(Duration::new(10, 0), clientgen(&keys, addr)).await {
            panic!("Timeout connection");
        }
        let _ = fs::remove_file("authorized_keys");
        Ok(())
    }
    #[test]
    #[cfg(feature = "rand")]
    fn checkinputkeys() -> Result<(), KyberError> {
        let mut rng = rand_core::OsRng::default();
        let keys = keypair(&mut rng);
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
        assert_eq!(keys, keys2);
        let _ = fs::remove_file(PRIVATEKEY_TEST);
        let _ = fs::remove_file(PUBLICKEY_TEST);
        Ok(())
    }
    #[tokio::test]
    #[cfg(all(feature = "server", feature = "client"))]
    async fn testpeer() -> Result<(), KyberError> {
        use tokio::task::JoinSet;

        let crypto = rustls::crypto::aws_lc_rs::default_provider();
        let _ = crypto.install_default();
        let mut set = JoinSet::new();
        set.spawn(server());
        set.spawn(client());
        let mut v = set.join_all().await.into_iter();
        let _ = match (v.next(), v.next()) {
            (Some(Ok(a)), Some(Ok(b))) => (a, b),
            (Some(Err(e)), _) => return Err(e),
            _ => return Err(KyberError::InvalidInput),
        };
        Ok(())
    }
}
