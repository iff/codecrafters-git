use anyhow::Context;
use sha1::{Digest, Sha1};
use std::ffi::CString;
use std::{
    fmt, fs,
    io::{BufRead, BufReader, Read, Write},
};

use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};

pub(crate) fn to_stdout(content: String) -> anyhow::Result<(), anyhow::Error> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    write!(stdout, "{}", content)?;
    Ok(())
}

#[derive(PartialEq)]
pub(crate) enum ObjectType {
    #[allow(dead_code)]
    Commit,
    #[allow(dead_code)]
    Tree,
    Blob,
    #[allow(dead_code)]
    Tag,
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectType::Commit => write!(f, "commit"),
            ObjectType::Tree => write!(f, "tree"),
            ObjectType::Blob => write!(f, "blob"),
            ObjectType::Tag => write!(f, "tag"),
        }
    }
}

fn object_path(hash: &str) -> String {
    format!(".git/objects/{}/{}", &hash[..2], &hash[2..])
}

pub(crate) struct Object {
    #[allow(dead_code)]
    object_type: ObjectType,
    // TODO usize vs u64?
    size: usize,
    hash: [u8; 20],
    // TODO refactor later - does not really make sense to be here
    compressed: Vec<u8>,
}

pub(crate) struct TreeObject {
    pub(crate) mode: u32,
    pub(crate) name: String, // TODO
    pub(crate) sha_bytes: [u8; 20],
}

impl TreeObject {
    pub fn read(object: &Object) -> anyhow::Result<Vec<Self>> {
        assert!(object.object_type == ObjectType::Tree);

        let z = ZlibDecoder::new(&object.compressed[..]);
        let mut r = BufReader::new(z);

        // skip header
        r.skip_until(0)?;

        let mut result = Vec::new();

        while !r.fill_buf().unwrap().is_empty() {
            let mut meta = Vec::new();
            r.read_until(0, &mut meta).expect("meta data with \\0");
            let meta = String::from(
                CString::from_vec_with_nul(meta)
                    .expect("cstring")
                    .to_str()?,
            );

            let Some((mode, name)) = meta.split_once(' ') else {
                return Err(anyhow::Error::msg(format!("cant parse header {}", meta)));
            };
            let mode = mode.parse::<u32>()?;

            let mut sha_bytes = [0; 20];
            r.read_exact(&mut sha_bytes)?;

            result.push(TreeObject {
                mode,
                name: name.to_string(),
                sha_bytes,
            });
        }

        Ok(result)
    }
}

impl Object {
    // TODO how do we distinguish between types we want to create
    pub fn from_path(path: &str) -> anyhow::Result<Object> {
        let file = fs::File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut data = Vec::new();
        let read_size = reader.read_to_end(&mut data)?;

        let buf = Vec::new();
        let mut writer = GitObjectWriter::new(buf);
        writer.write_all(format!("{} {}\0", ObjectType::Blob, read_size).as_bytes())?;
        let (compressed, hash) = writer.finish()?;

        Ok(Object {
            object_type: ObjectType::Blob,
            size: read_size,
            hash,
            compressed,
        })
    }

    pub fn from_hash(hash: &str) -> anyhow::Result<Object> {
        // TODO this should just populate the object and then we can get/parse the content?
        let file = std::fs::File::open(object_path(hash))?;
        let mut r = BufReader::new(file);
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;
        let compressed_content = data.clone();

        let z = ZlibDecoder::new(&data[..]);
        let mut r = BufReader::new(z);

        // extract content: blob <size>\0<content>
        let mut header = Vec::new();
        r.read_until(0, &mut header)?;
        let content = String::from(CString::from_vec_with_nul(header)?.to_str()?);

        let Some((object_type, size)) = content.split_once(' ') else {
            return Err(anyhow::Error::msg(format!("cant parse header {}", content)));
        };
        let ot = match object_type {
            "commit" => ObjectType::Commit,
            "tree" => ObjectType::Tree,
            "blob" => ObjectType::Blob,
            "tag" => ObjectType::Tag,
            _ => return Err(anyhow::Error::msg("unable to parse object type")),
        };
        // assert!(ot == ObjectType::Blob);

        let size = size.parse::<usize>()?;

        Ok(Object {
            object_type: ot,
            size,
            hash: hex::decode(hash).context("decoding hash")?[0..20]
                .try_into()
                .with_context(|| format!("coercing hash to u8 array: {}", hash))?,
            compressed: compressed_content,
        })
    }

    pub fn content(&self) -> anyhow::Result<String> {
        assert!(self.object_type == ObjectType::Blob);
        let z = ZlibDecoder::new(&self.compressed[..]);
        let mut r = BufReader::new(z);

        // skip header
        r.skip_until(0)?;

        let mut content = Vec::new();
        r.take(self.size.try_into()?).read_to_end(&mut content)?;
        assert!(content.len() == self.size);
        let content = str::from_utf8(content.as_slice())?;
        Ok(content.to_string())
    }

    pub fn hash_str(&self) -> String {
        hex::encode(self.hash)
    }

    pub fn write(&self) -> anyhow::Result<()> {
        let hash_str = hex::encode(self.hash);
        fs::create_dir_all(format!(".git/objects/{}", &hash_str[..2]))?;
        let mut out = fs::File::create(object_path(&hash_str))?;

        out.write_all(self.compressed.as_slice())?;
        Ok(())
    }
}

pub struct GitObjectWriter<W: Write> {
    compressor: ZlibEncoder<W>,
    hasher: Sha1,
}

impl<W: Write> GitObjectWriter<W> {
    pub fn new(writer: W) -> Self {
        GitObjectWriter {
            compressor: ZlibEncoder::new(writer, Compression::default()),
            hasher: Sha1::new(),
        }
    }

    pub fn finish(self) -> std::io::Result<(W, [u8; 20])> {
        let writer = self.compressor.finish()?;
        let hash = self.hasher.finalize();
        Ok((writer, hash.into()))
    }
}

impl<W: Write> Write for GitObjectWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.compressor.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.compressor.flush()
    }
}
