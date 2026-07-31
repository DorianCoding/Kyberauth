use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, KeyInit},
};
use hex;
use quinn::{RecvStream, SendStream};
use safe_pqc_kyber::*;
use std::{
    io::{Read, Write},
    net::SocketAddr,
};
use zeroize::Zeroize;

use crate::r#struct::{Error, RawError, Result};
const NONCESIZE: usize = 96 / 8;
const MAXSIZE: usize = 10000;
#[derive(Debug, Zeroize)]
pub struct Connection {
    #[zeroize(skip)]
    recv: RecvStream,
    #[zeroize(skip)]
    sender: SendStream,
    #[zeroize(skip)]
    pub peer_addr: SocketAddr,
    pub pubkey: String,
    aeskey: [u8; KYBER_SSBYTES],
}
impl Connection {
    /// Flush and shutdown the socket
    /* pub async fn clean(&mut self) -> io::Result<()> {
        let socket = &mut self.socket;
        socket.flush().await?;
        socket.shutdown().await?;
        Ok(())
    } */
    /// Create a new connection with pubkey and to transmit aeskey. AES key is hidden and cannot be retrieved for security reasons.
    #[allow(dead_code)]
    pub(crate) fn new(
        recv: RecvStream,
        sender: SendStream,
        peer_addr: SocketAddr,
        pubkey: String,
        aeskey: [u8; KYBER_SSBYTES],
    ) -> Self {
        Connection {
            recv,
            sender,
            peer_addr,
            pubkey,
            aeskey,
        }
    }
    /// Get peer public key
    pub fn getpeerkey(&self, hex: bool) -> Result<Vec<u8>> {
        if hex {
            Ok(self.pubkey.clone().into_bytes())
        } else {
            Ok(hex::decode(self.pubkey.clone())
                .map_err(|d| Error::from(d))?
                .to_vec())
        }
    }
    pub fn getrecv(&mut self) -> &mut SendStream {
        &mut self.sender
    }
    pub fn getsend(&mut self) -> &mut RecvStream {
        &mut self.recv
    }
    pub fn getpeer(&self) -> SocketAddr {
        self.peer_addr
    }
    /// Encrypt data via AES key into the connection, might return an error.
    pub async fn senddata<T>(&mut self, text: T) -> Result<()>
    where
        T: Read,
    {
        let mut cipher = Vec::new();
        self.encryptdata(text, &mut cipher)?;
        self.sender
            .write_all(&cipher)
            .await
            .map_err(|d| Error::from(d))?;
        //self.socket.flush().await?;
        Ok(())
    }
    /// Receive encrypted data and decrypt it. No reallocated. Might return an error.
    pub async fn receivedata<T>(&mut self, writer: &mut T) -> Result<()>
    where
        T: Write,
    {
        let mut vec = self
            .recv
            .read_to_end(MAXSIZE)
            .await
            .map_err(|d| Error::from(d))?;
        vec.shrink_to_fit();
        self.decryptdata(vec.as_slice(), writer)
    }
    /// Encrypt data without sending to the socket. Might return an error.
    pub fn encryptdata<T, U>(&self, input: T, socket: &mut U) -> Result<()>
    where
        T: Read,
        U: Write,
    {
        // Alternatively, the key can be transformed directly from a byte slice
        // (panicks on length mismatch):
        let mut reader = input.take(MAXSIZE.saturating_add(1).try_into().unwrap_or(u64::MAX));
        let mut input = Vec::new();
        if reader.read_to_end(&mut input).map_err(|d| Error::from(d))? > MAXSIZE {
            return Err(Error {
                repr: Box::new(RawError::Maxsize),
            });
        }
        let key = Aes256Gcm::new_from_slice(&self.aeskey).map_err(|_| Error {
            repr: Box::new(RawError::InvalidData("Invalid key".to_string())),
        })?;
        let nonce = Nonce::generate();
        let mut ciphertext = key
            .encrypt(&nonce, input.as_ref())
            .map_err(|d| Error::from(d))?;
        let mut finale: Vec<u8> = Vec::new();
        finale.extend_from_slice(nonce.as_ref());
        finale.append(&mut ciphertext);
        socket.write_all(&finale).map_err(|d| d.into())
    }
    /// Decrypt data without sending to the socket. Might return an error.
    pub fn decryptdata<T, U>(&self, input: T, writer: &mut U) -> Result<()>
    where
        T: Read,
        U: Write,
    {
        let mut reader = input.take(MAXSIZE.saturating_add(1).try_into().unwrap_or(u64::MAX));
        let mut input = Vec::new();
        if reader.read_to_end(&mut input).map_err(|d| Error::from(d))? > MAXSIZE {
            return Err(Error {
                repr: Box::new(RawError::Maxsize),
            });
        }
        let key = Aes256Gcm::new_from_slice(&self.aeskey).map_err(|_| Error {
            repr: Box::new(RawError::InvalidData("Invalid key".to_string())),
        })?;
        let nonce = Nonce::try_from(&input[..NONCESIZE]).map_err(|_| Error {
            repr: Box::new(RawError::InvalidData("Invalid nonce".to_string())),
        })?;
        let input: &[u8] = &input[NONCESIZE..];
        let plaintext = key
            .decrypt(&nonce, input.as_ref())
            .map_err(|d| Error::from(d))?;
        writer.write_all(&plaintext).map_err(|d| d.into())
    }
}
