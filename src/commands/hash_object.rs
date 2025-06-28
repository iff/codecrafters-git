use sha1::{Digest, Sha1};
use std::{
    fs,
    io::{BufReader, Read, Write},
};

pub(crate) fn invoke(write: bool, path: &str) -> anyhow::Result<()> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;

    let mut hasher = Sha1::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let hash_str = hex::encode(hash);

    if write {
        fs::create_dir_all(format!(".git/objects/{}", &hash_str[..2],))?;
        let mut out = fs::File::create(format!(
            ".git/objects/{}/{}",
            &hash_str[..2],
            &hash_str[2..]
        ))?;
        out.write_all(hash_str.as_bytes())?;
    }

    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    write!(stdout, "{}", hash_str)?;

    Ok(())
}
