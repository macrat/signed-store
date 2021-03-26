use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use actix_files::NamedFile;

#[derive(std::clone::Clone)]
pub struct Store {
    pub ttl: Duration,
    path: PathBuf,
}

impl Store {
    pub fn new<P: AsRef<OsStr> + ?Sized>(path: &P, ttl: Duration) -> anyhow::Result<Store> {
        Ok(Store {
            ttl: ttl,
            path: Path::new(path).to_path_buf(),
        })
    }

    fn key_to_path(&self, key: &str) -> std::path::PathBuf {
        self.path.join(
            uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, key.as_bytes())
                .to_hyphenated()
                .encode_lower(&mut uuid::Uuid::encode_buffer()),
        )
    }

    pub fn save(&self, key: &str, data: &[u8]) -> anyhow::Result<()> {
        File::create(self.key_to_path(key))?.write_all(data)?;

        Ok(())
    }

    fn is_expired<P: AsRef<Path>>(&self, path: &P) -> bool {
        let metadata = fs::metadata(&path);
        if let Err(_) = metadata {
            return true;
        }
        let metadata = metadata.expect("failed to get metadata");

        let accessed = metadata.accessed();
        if let Err(_) = accessed {
            return true;
        }
        let accessed = accessed.expect("failed to get atime");

        match accessed.elapsed() {
            Ok(elapsed) if elapsed <= self.ttl => false,
            _ => true,
        }
    }

    pub fn open(&self, key: &str) -> anyhow::Result<NamedFile> {
        let path = self.key_to_path(key);

        if self.is_expired(&path) {
            fs::remove_file(&path)?;
        } else {
            filetime::set_file_atime(&path, filetime::FileTime::now())?;
        }

        Ok(NamedFile::open(path)?)
    }

    pub fn delete(&self, key: &str) -> anyhow::Result<()> {
        fs::remove_file(self.key_to_path(key))?;

        Ok(())
    }

    pub fn prune(&self) -> anyhow::Result<i64> {
        let mut count = 0;

        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            if self.is_expired(&entry.path()) {
                fs::remove_file(entry.path())?;
                count += 1;
            }
        }

        Ok(count)
    }
}
