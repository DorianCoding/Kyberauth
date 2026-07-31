#[cfg(target_family = "unix")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_family = "windows")]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(target_family = "windows")]
use std::os::windows::prelude::*;
use std::{
    fmt::Display,
    fs::{self, File},
    io::ErrorKind::InvalidInput,
    path::{Path, PathBuf},
};

use crate::r#struct::RawError::{InvalidData, Maxsize};
#[derive(Debug)]
pub struct SecureFile {
    file: File,
    path: PathBuf,
    delete: bool,
}
impl SecureFile {
    pub fn getpath(&self) -> &Path {
        &self.path
    }
    pub fn getfile(&self) -> &File {
        &self.file
    }
    pub fn getmutfile(&mut self) -> &mut File {
        &mut self.file
    }
    pub fn keep(&mut self) {
        self.delete = false;
    }
    pub fn markdelete(&mut self) {
        self.delete = true;
    }
    pub fn new(path: PathBuf, file: File, delete: bool) -> Self {
        Self { path, file, delete }
    }
    /// Create a file
    /// # Examples
    /// ```rust
    /// use kyberauth::r#struct::SecureFile;
    /// use std::path::Path;
    /// SecureFile::createfrompath(&Path::join(&std::env::temp_dir(),"test.txt"),false,true).unwrap();
    /// ```
    pub fn createfrompath(file: &Path, secure: bool, delete: bool) -> Result<SecureFile> {
        #[cfg(target_family = "windows")]
        #[allow(unreachable_code)]
        {
            return Ok(SecureFile::new(
                file.to_path_buf(),
                fs::OpenOptions::new()
                    .create(true)
                    .attributes(winapi::FILE_ATTRIBUTE_READONLY)
                    .write(true)
                    .open(&file)
                    .map_err(|d| Error::from(d))?,
            ));
        }
        #[cfg(target_family = "unix")]
        #[allow(unreachable_code)]
        {
            let umode: u32 = if secure { 0o600 } else { 0o644 };
            return Ok(SecureFile::new(
                file.to_path_buf(),
                fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .mode(umode)
                    .open(file)
                    .map_err(|d| Error::from(d))?,
                delete,
            ));
        }
        #[allow(unreachable_code)]
        Ok(SecureFile::new(
            file.to_path_buf(),
            fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(file)
                .map_err(|d| Error::from(d))?,
            delete,
        ))
    }
}
impl Drop for SecureFile {
    fn drop(&mut self) {
        if self.delete {
            let _ = fs::remove_file(self.path.as_path());
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RawError {
    Maxsize,
    InvalidData(String),
}
impl Display for RawError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Maxsize => f.write_str("Exceed MAX SIZE allowed."),
            InvalidData(a) => write!(f, "Invalid data. {a}"),
        }
    }
}
impl From<quinn::WriteError> for Error {
    fn from(value: quinn::WriteError) -> Self {
        Error {
            repr: Box::new(std::io::Error::new(InvalidInput, value.to_string())),
        }
    }
}
impl From<quinn::ReadError> for Error {
    fn from(value: quinn::ReadError) -> Self {
        Error {
            repr: Box::new(std::io::Error::new(InvalidInput, value.to_string())),
        }
    }
}
impl From<hex::FromHexError> for Error {
    fn from(value: hex::FromHexError) -> Self {
        Error {
            repr: Box::new(std::io::Error::new(InvalidInput, value.to_string())),
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error {
            repr: Box::new(value),
        }
    }
}
impl From<quinn::ReadExactError> for Error {
    fn from(value: quinn::ReadExactError) -> Self {
        Error {
            repr: Box::new(std::io::Error::new(InvalidInput, value.to_string())),
        }
    }
}
impl From<quinn::ReadToEndError> for Error {
    fn from(value: quinn::ReadToEndError) -> Self {
        Error {
            repr: Box::new(std::io::Error::new(InvalidInput, value.to_string())),
        }
    }
}
impl From<aes_gcm::Error> for Error {
    fn from(value: aes_gcm::Error) -> Self {
        Error {
            repr: Box::new(std::io::Error::new(InvalidInput, value.to_string())),
        }
    }
}
pub type Result<T> = core::result::Result<T, Error>;
impl std::error::Error for RawError {}
impl std::error::Error for Error {}
#[derive(Debug)]
pub struct Error {
    pub(crate) repr: Box<dyn std::error::Error + Send>,
}
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.repr)
    }
}
