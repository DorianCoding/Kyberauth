use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use safe_pqc_kyber::*;
use sha3::{Digest, Sha3_256};
use std::fs;
use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};
use tokio::io::AsyncReadExt;
async fn keyhandshakeread(socket: &Connection) -> io::Result<(RecvStream, SendStream, Vec<u8>)> {
    //let _ = socket.set_nodelay(true);
    let mut pubkey: Vec<u8> = Vec::with_capacity(KYBER_PUBLICKEYBYTES);
    pubkey.clear();
    pubkey.resize(KYBER_PUBLICKEYBYTES, 0);
    let bi = socket
        .accept_bi()
        .await
        .map_err(|_| io::Error::from(ErrorKind::NotConnected))?;
    let (send, mut recv) = bi;
    println!("Waiting for data");
    recv.read_buf(&mut pubkey)
        .await
        .map_err(|_| io::Error::from(ErrorKind::InvalidData))?;
    Ok((recv, send, pubkey))
}
async fn keyhandshakewrite(
    socket: &mut SendStream,
    keypublic: &[u8; KYBER_PUBLICKEYBYTES],
) -> io::Result<()> {
    socket
        .write_all(keypublic)
        .await
        .map_err(|_| io::Error::from(ErrorKind::InvalidData))
}
async fn checkkeys<T>(
    send: &mut SendStream,
    recv: &mut RecvStream,
    key: &Keypair,
    pubkey: T,
) -> io::Result<[u8; KYBER_SSBYTES]>
where
    T: AsRef<[u8]>,
{
    let pubkey = pubkey.as_ref();
    //let _ = socket.set_nodelay(true);
    let mut bob = Ake::new();
    let mut client_init: Vec<u8> = Vec::with_capacity(AKE_INIT_BYTES);
    client_init.clear();
    client_init.resize(AKE_INIT_BYTES, 0);
    recv.read_buf(&mut client_init)
        .await
        .map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
    //The key was read
    if pubkey.len() != KYBER_PUBLICKEYBYTES {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    let pubkey: [u8; KYBER_PUBLICKEYBYTES] = pubkey[..KYBER_PUBLICKEYBYTES].try_into().unwrap();
    if client_init.len() != AKE_INIT_BYTES {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    let client_init: [u8; AKE_INIT_BYTES] = client_init[..AKE_INIT_BYTES].try_into().unwrap();
    let mut rng = rand_core::OsRng::default();
    let server_send = bob.server_receive(client_init, &pubkey, &key.secret, &mut rng);
    if server_send.is_err() {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    send.write_all(&server_send.unwrap())
        .await
        .map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
    //socket.flush().await?;
    Ok(bob.shared_secret)
}
/// Verify peer key is allowed in authorized_keys
pub fn verifypubkey<T>(pubkey: T) -> bool
where
    T: AsRef<[u8]>,
{
    let pubkey = pubkey.as_ref();
    let mut read = fs::read_to_string("authorized_keys").unwrap_or_default();
    read = String::from(read.trim());
    if read.is_empty() {
        return false;
    }
    // create a SHA3-256 object
    let mut hasher = Sha3_256::new();

    // write input message
    hasher.update(pubkey);

    // read hash digest
    let result = hex::encode(hasher.finalize());
    for line in read.lines() {
        if line.split(" ").collect::<Vec<_>>()[0].trim() == result {
            return true;
        }
    }
    false
}
/// Start to listen to the socket addr
pub async fn startlistener(addr: SocketAddr) -> io::Result<Endpoint> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|_| io::Error::from(ErrorKind::ResourceBusy))?;
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let config = ServerConfig::with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(key))
        .map_err(|_| io::Error::from(ErrorKind::ResourceBusy))?;
    Endpoint::server(config, addr)
}
/// Accept incoming connection, check pub key and generate an encrypted channel. Udp socket is not connected.
#[cfg(feature = "aes")]
pub async fn listener(
    key: &Keypair,
    listener: Connection,
    forceyes: bool,
) -> io::Result<(SocketAddr, crate::aes::Connection)> {
    println!("Listening");
    let (mut recv, mut send, pubkey) = keyhandshakeread(&listener).await?;
    if !forceyes && !verifypubkey(&pubkey) {
        //socket.shutdown().await?;
        return Err(Error::new(ErrorKind::InvalidData, "Key not found"));
    }
    /* if let Err(_) = listener.connect(peer_addr).await {
        return Err(Error::new(
            ErrorKind::ConnectionRefused,
            "Connection refused",
        ));
    } */
    let peer_addr = listener.remote_address();
    keyhandshakewrite(&mut send, &key.public).await?;
    let hexpub = hex::encode(pubkey.clone());
    let sharedsecret = checkkeys(&mut send, &mut recv, key, &pubkey).await?;
    let elem = crate::aes::Connection::new(recv, send, peer_addr, hexpub, sharedsecret);
    Ok((peer_addr, elem))
}
