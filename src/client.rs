use quinn::crypto::rustls::QuicClientConfig;
use quinn::{Endpoint, RecvStream, SendStream};
use rustls::ClientConfig;
use safe_pqc_kyber::*;
use std::io::ErrorKind;
use std::sync::Arc;
use std::{io, net::SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

async fn keyhandshake(
    sender: &mut SendStream,
    receiver: &mut RecvStream,
    key: &[u8; KYBER_PUBLICKEYBYTES],
) -> io::Result<Vec<u8>> {
    //let _ = socket.set_nodelay(true);
    //The key is sent
    sender.write_all(key).await?;
    //socket.flush().await?;
    let mut pubkey: Vec<u8> = Vec::with_capacity(KYBER_PUBLICKEYBYTES);
    pubkey.clear();
    pubkey.resize(KYBER_PUBLICKEYBYTES, 0);
    receiver
        .read_exact(&mut pubkey)
        .await
        .map_err(|_| io::Error::from(ErrorKind::InvalidData))?;
    //The key was read
    Ok(pubkey)
}
async fn checkkeys<T>(
    sender: &mut SendStream,
    receiver: &mut RecvStream,
    key: &Keypair,
    pubkey: T,
) -> io::Result<[u8; KYBER_SSBYTES]>
where
    T: AsRef<[u8]>,
{
    let pubkey = pubkey.as_ref();
    //let _ = socket.set_nodelay(true);
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let pubkey: [u8; KYBER_PUBLICKEYBYTES] = pubkey[..KYBER_PUBLICKEYBYTES]
        .try_into()
        .unwrap_or([0; KYBER_PUBLICKEYBYTES]);
    let client_init = alice.client_init(&pubkey, &mut rng);
    if pubkey == [0; KYBER_PUBLICKEYBYTES] {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    sender.write_all(&client_init).await?;
    //socket.flush().await?;
    let mut server_answer: Vec<u8> = Vec::with_capacity(AKE_RESPONSE_BYTES);
    server_answer.clear();
    server_answer.resize(AKE_RESPONSE_BYTES, 0);
    let _ = receiver
        .read_exact(&mut server_answer)
        .await
        .map_err(|_| io::Error::from(ErrorKind::InvalidData))?;
    //The key was read
    let server_answer: [u8; AKE_RESPONSE_BYTES] = server_answer[..AKE_RESPONSE_BYTES]
        .try_into()
        .unwrap_or([0; AKE_RESPONSE_BYTES]);
    let result = alice.client_confirm(server_answer, &key.secret);
    if server_answer == [0; AKE_RESPONSE_BYTES] || result.is_err() {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    Ok(alice.shared_secret)
}

pub async fn connecter(key: &Keypair, addr: SocketAddr) -> io::Result<crate::aes::Connection> {
    /* let socket = TcpSocket::new_v4()?;
    if cfg!(unix) {
        socket.set_reuseport(false)?;
    }
    socket.set_reuseaddr(false)?; */
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(crate::SkipServerVerification::new())
        .with_no_client_auth();
    let mut client = Endpoint::client((std::net::Ipv6Addr::UNSPECIFIED, 0).into())?;
    let quic = QuicClientConfig::try_from(config).unwrap();
    let quic = quinn::ClientConfig::new(Arc::new(quic));
    client.set_default_client_config(quinn::ClientConfig::from(quic));
    let client = client
        .connect(addr, "localhost")
        .map_err(|_| io::Error::from(ErrorKind::ConnectionRefused))?
        .await
        .map_err(|_| io::Error::from(ErrorKind::ConnectionRefused))?;
    //let mut stream: TcpStream = Incoming::connect(addr).await?; //TODO: Implements a timeout
    let (mut send, mut recv) = client
        .open_bi()
        .await
        .map_err(|_| io::Error::from(ErrorKind::ConnectionRefused))?;
    let pubkey = keyhandshake(&mut send, &mut recv, &key.public).await?;
    let hexpub = hex::encode(pubkey.clone());
    let sharedsecret = checkkeys(&mut send, &mut recv, &key, &pubkey).await?;
    /* let peer_addr = stream.peer_addr();
    if peer_addr.is_err() {
        return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
    } */
    let elem = crate::aes::Connection::new(recv, send, addr, hexpub, sharedsecret);
    Ok(elem)
}
