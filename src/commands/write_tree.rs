use std::{
    cmp::Ordering,
    ffi::OsString,
    fs::{self, DirEntry, Metadata},
    io::Write,
    path::Path,
};

use anyhow::Context;

use crate::object::{to_stdout, GitObjectWriter, Object, ObjectType};

fn write_tree(path: &Path) -> anyhow::Result<Option<[u8; 20]>> {
    let mut tree_objects = Vec::new();

    let mut entries: Vec<(DirEntry, OsString, Metadata)> = Vec::new();
    for dir_entry in fs::read_dir(path)? {
        let entry = dir_entry?;
        let file_name = entry.file_name();
        let meta = entry.metadata()?;
        entries.push((entry, file_name, meta));
    }

    // explicitly handle directories to include trailing slash when sorting
    // see `base_name_compare` in `tree.c`
    entries.sort_unstable_by(|a, b| {
        let aa = a.1.as_encoded_bytes();
        let bb = b.1.as_encoded_bytes();
        let prefix_len = std::cmp::min(aa.len(), bb.len());

        // should match memcmp(name1, name2, len)
        // only continue if strings are the same on the shared length
        match aa[..prefix_len].cmp(&bb[..prefix_len]) {
            Ordering::Equal => {
                // handle this case here but would also be correct otherwise
                // comparing \0 with \0 below
                if aa.len() == bb.len() {
                    return Ordering::Equal;
                }
                // else continue
            }
            o => return o,
        }

        // otherwise check next character
        // the directory special case: git stores dirs without trailing slashes but for the purpose
        // of sorting they should be treated as if they have a trailing / to ensure lexicographic
        // ordering (test/ comes before test.txt)
        let c1 = if let Some(c) = aa.get(prefix_len).copied() {
            c
        } else if a.2.is_dir() {
            b'/'
        } else {
            b'\0'
        };

        let c2 = if let Some(c) = bb.get(prefix_len).copied() {
            c
        } else if b.2.is_dir() {
            b'/'
        } else {
            b'\0'
        };

        c1.cmp(&c2)
    });

    for (entry, file_name, meta) in entries {
        if file_name == ".git" {
            continue;
        }

        // TODO executable is 100755
        // TODO 120000 is a symlink
        let mode = if meta.is_dir() { "40000" } else { "100644" };

        let path = entry.path();

        let hash = if meta.is_dir() {
            // If the entry is a directory, recursively create a tree object and record its SHA-1 hash
            // handle empty directory here
            let Some(hash) = write_tree(&path)? else {
                continue;
            };
            hash
        } else {
            // If the entry is a file, create a blob object and record its SHA-1 hash
            let blob = Object::from_path(path.to_str().context("getting path as string")?)?;
            blob.write()?;
            blob.hash()
        };

        tree_objects.extend(mode.as_bytes());
        tree_objects.push(b' ');
        tree_objects.extend(file_name.as_encoded_bytes());
        tree_objects.push(0);
        tree_objects.extend(hash);
    }

    let tree_size = tree_objects.len();
    if tree_size == 0 {
        Ok(None)
    } else {
        let buf = Vec::new();
        let mut writer = GitObjectWriter::new(buf);
        writer.write_all(format!("{} {}\0", ObjectType::Tree, tree_size).as_bytes())?;
        writer.write_all(&tree_objects)?;
        let (compressed, hash) = writer.finish()?;

        let object = Object::new_tree(tree_size, hash, &compressed);
        object.write()?;
        Ok(Some(object.hash()))
    }
}

pub(crate) fn invoke() -> anyhow::Result<()> {
    // we won't implement a staging area
    // just assume that all files in the working directory are staged.
    // TODO error if empty?
    if let Some(hash) = write_tree(Path::new("."))? {
        to_stdout(hex::encode(hash))?;
    }
    Ok(())
}
