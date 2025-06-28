use sha1::{Digest, Sha1};
use std::{
    fs,
    io::{BufReader, Read, Write},
};

use flate2::{write::ZlibEncoder, Compression};

pub(crate) fn invoke(write: bool, path: &str) -> anyhow::Result<()> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new();
    let read_size = reader.read_to_end(&mut data)?;

    let mut hasher = Sha1::new();

    // extract content: blob <size>\0<content>
    let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
    write!(z, "blob {}\0", read_size)?;
    hasher.update(format!("blob {}\0", read_size));
    let _ = z.write(data.as_slice())?;
    hasher.update(&data);
    let compressed = z.finish()?;

    let hash = hasher.finalize();
    let hash_str = hex::encode(hash);

    if write {
        fs::create_dir_all(format!(".git/objects/{}", &hash_str[..2],))?;
        let mut out = fs::File::create(format!(
            ".git/objects/{}/{}",
            &hash_str[..2],
            &hash_str[2..]
        ))?;

        out.write_all(compressed.as_slice())?;
    }

    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    write!(stdout, "{}", hash_str)?;

    Ok(())
}
