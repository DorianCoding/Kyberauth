use pqc_kyber::*;
use sha3::{Digest, Sha3_256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use zeroize::Zeroize;
const CONNECTION_TIME: u64 = 60;
use std::fs;
use std::{
    net::SocketAddr,
    io::{self, Error, ErrorKind},
    num::IntErrorKind,
    time::Duration,
};
async fn keyhandshake(socket: &mut TcpStream, key: &Keypair) -> io::Result<Vec<u8>> {
    let _ = socket.set_nodelay(true);
    socket.readable().await?;
    let mut pubkey: Vec<u8> = Vec::with_capacity(KYBER_PUBLICKEYBYTES);
    pubkey.clear();
    pubkey.resize(KYBER_PUBLICKEYBYTES, 0);
    let _ = socket.read_exact(&mut pubkey).await?;
    //The key was read
    socket.writable().await?;
    socket.write_all(&key.public).await?;
    socket.flush().await?;
    Ok(pubkey)
}
async fn checkkeys(
    socket: &mut TcpStream,
    key: &Keypair,
    pubkey: Vec<u8>,
) -> io::Result<[u8; KYBER_SSBYTES]> {
    let _ = socket.set_nodelay(true);
    socket.readable().await?;
    let mut bob = Ake::new();
    let mut client_init: Vec<u8> = Vec::with_capacity(AKE_INIT_BYTES);
    client_init.clear();
    client_init.resize(AKE_INIT_BYTES, 0);
    let _ = socket.read_exact(&mut client_init).await?;
    //The key was read
    let pubkey: [u8; KYBER_PUBLICKEYBYTES] = pubkey[..KYBER_PUBLICKEYBYTES]
        .try_into()
        .expect("Invalid data");
    let client_init: [u8; AKE_INIT_BYTES] = client_init[..AKE_INIT_BYTES]
        .try_into()
        .expect("Invalid data");
    let mut rng = rand::thread_rng();
    let server_send = bob
        .server_receive(client_init, &pubkey, &key.secret, &mut rng)
        .expect("Invalid data");
    socket.writable().await?;
    socket.write_all(&server_send).await?;
    socket.flush().await?;
    Ok(bob.shared_secret)
}
pub fn verifypubkey(pubkey: &[u8]) -> bool {
    let mut read = fs::read_to_string("authorized_keys").unwrap_or_default();
    read = String::from(read.trim());
    if read.len() == 0 {
        return false;
    }
    // create a SHA3-256 object
    let mut hasher = Sha3_256::new();

    // write input message
    hasher.update(&pubkey);

    // read hash digest
    let result = hex::encode(hasher.finalize());
    for line in read.lines() {
        if line.split(" ").collect::<Vec<_>>()[0].trim() == result {
            return true;
        }
    }
    false
}
pub async fn startlistener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = TcpSocket::new_v4()?;
    if cfg!(unix) {
        socket.set_reuseport(false)?;
    }
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;
    Ok(listener)
}
pub async fn listener(key: &Keypair, listener: TcpListener, test: bool) -> io::Result<crate::aes::Connection> {
    loop {
        let (mut socket, _) = listener.accept().await?;
        let peer_addr=socket.peer_addr().unwrap();
        let pubkey = keyhandshake(&mut socket, key).await?;
        if !test && !verifypubkey(&pubkey) {
            socket.shutdown().await?;
            return Err(Error::new(ErrorKind::InvalidData,"Key not found"));
        }
        let hexpub=hex::encode(pubkey.clone());
        let sharedsecret = checkkeys(&mut socket, key, pubkey).await?;
        let elem=crate::aes::Connection::new(socket, peer_addr, hexpub, sharedsecret);
        return Ok(elem);
    }
}
