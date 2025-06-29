use crate::object::{to_stdout, Object};

pub(crate) fn invoke(write: bool, path: &str) -> anyhow::Result<()> {
    let object = Object::from_path(path)?;
    if write {
        object.write()?;
    }

    let hash = object.hash_str();
    to_stdout(hash)?;

    Ok(())
}
