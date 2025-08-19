use std::{fs, io::Write, path::Path};

use crate::object::{to_stdout, GitObjectWriter, Object, ObjectType};

fn write_tree(path: &Path) -> anyhow::Result<Option<[u8; 20]>> {
    let mut tree_objects = Vec::new();
    for entries in fs::read_dir(path)? {
        let entry = entries?;
        let file_name = entry.file_name();
        let meta = entry.metadata()?;

        if file_name == ".git" {
            continue;
        }

        // TODO executable is 100755
        // TODO 120000 is a symlink
        let mode = if meta.is_dir() { "40000" } else { "100644" };

        let path = entry.path();

        let hash = if meta.is_dir() {
            // If the entry is a directory, recursively create a tree object and record its SHA-1 hash
            let Some(hash) = write_tree(&path)? else {
                // empty directory, so don't include in parent
                continue;
            };
            hash
        } else {
            // If the entry is a file, create a blob object and record its SHA-1 hash
            let o = Object::from_path(path.to_str().expect("path must be valid"))?;
            o.write()?;
            o.hash()
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
    if let Some(hash) = write_tree(Path::new("."))? {
        to_stdout(hex::encode(hash))?;
    }
    Ok(())
}
