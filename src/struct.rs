#[cfg(target_family = "unix")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_family = "windows")]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(target_family = "windows")]
use std::os::windows::prelude::*;
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};
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
    pub fn createfrompath(file: &Path, secure: bool, delete: bool) -> std::io::Result<SecureFile> {
        #[cfg(target_family = "windows")]
        #[allow(unreachable_code)]
        {
            return Ok(SecureFile::new(
                file.to_path_buf(),
                fs::OpenOptions::new()
                    .create(true)
                    .attributes(winapi::FILE_ATTRIBUTE_READONLY)
                    .write(true)
                    .open(&file)?,
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
                    .open(file)?,
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
                .open(file)?,
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
