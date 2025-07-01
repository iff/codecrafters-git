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
    hash: Vec<u8>,
    // TODO refactor later - does not really make sense to be here
    compressed: Vec<u8>,
}

pub(crate) struct TreeObject {
    pub(crate) mode: u32,
    pub(crate) name: String, // TODO
    pub(crate) sha_bytes: [u8; 20],
}

impl TreeObject {
    // pub fn from_bytes(data: &Vec<u8>) -> anyhow::Result<Self> {
    //     let (meta, sha) = data.split_at(null);
    //     let (mode, name) = meta.split_at(' '.into());
    //     let mode = 40000;
    //     let name = str::from_utf8(&data[4..5])?.to_string();
    //     let byte_sha = sha;
    //     Ok(TreeObject {
    //         mode,
    //         name,
    //         sha_bytes: byte_sha,
    //     })
    // }
}

impl Object {
    // TODO how do we distinguish between types we want to create
    pub fn from_path(path: &str) -> anyhow::Result<Object> {
        let file = fs::File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut data = Vec::new();
        let read_size = reader.read_to_end(&mut data)?;

        let mut hasher = Sha1::new();
        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());

        // how do we do this in Rust?
        // this is a duplicated code, impl std::io::Write to save?
        write!(z, "{} {}\0", ObjectType::Blob, read_size)?;
        hasher.update(format!("{} {}\0", ObjectType::Blob, read_size));
        let _ = z.write(data.as_slice())?;
        hasher.update(&data);

        Ok(Object {
            object_type: ObjectType::Blob,
            size: read_size,
            hash: hasher.finalize().to_vec(),
            compressed: z.finish()?,
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
            hash: hash.to_owned().into(),
            compressed: compressed_content,
        })
    }

    pub fn content(&self) -> anyhow::Result<String> {
        let z = ZlibDecoder::new(&self.compressed[..]);
        let mut r = BufReader::new(z);

        // skip header
        r.skip_until(0)?;

        match self.object_type {
            ObjectType::Blob => {
                let mut content = Vec::new();
                r.take(self.size.try_into()?).read_to_end(&mut content)?;
                assert!(content.len() == self.size);
                let content = str::from_utf8(content.as_slice())?;
                Ok(content.to_string())
            }
            ObjectType::Tree => {
                let mut result = Vec::new();

                while !r.fill_buf().unwrap().is_empty() {
                    let mut meta = Vec::new();
                    r.read_until(0, &mut meta)?;
                    let meta = String::from(CString::from_vec_with_nul(meta)?.to_str()?);

                    let Some((mode, name)) = meta.split_once(' ') else {
                        return Err(anyhow::Error::msg(format!("cant parse header {}", meta)));
                    };
                    let mode = mode.parse::<u32>()?;

                    let mut sha_bytes = Vec::new();
                    r.read_until(b'\n', &mut sha_bytes)?;

                    result.push(TreeObject {
                        mode,
                        name: name.to_string(),
                        sha_bytes: sha_bytes[0..20].try_into()?,
                    });
                }

                // Ok(result)
                Err(anyhow::Error::msg(""))
            }
            ObjectType::Tag => Err(anyhow::Error::msg("reading tag not implemented yet")),
            ObjectType::Commit => Err(anyhow::Error::msg("reading commit not implemented yet")),
        }
    }

    pub fn tree_content(&self) -> anyhow::Result<Vec<TreeObject>> {
        let z = ZlibDecoder::new(&self.compressed[..]);
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

    pub fn hash_str(&self) -> String {
        hex::encode(&self.hash)
    }

    pub fn write(&self) -> anyhow::Result<()> {
        let hash_str = hex::encode(&self.hash);
        fs::create_dir_all(format!(".git/objects/{}", &hash_str[..2]))?;
        let mut out = fs::File::create(object_path(&hash_str))?;

        out.write_all(self.compressed.as_slice())?;
        Ok(())
    }
}
