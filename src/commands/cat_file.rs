use crate::object::to_stdout;
use crate::object::Object;

pub(crate) fn invoke(_pretty: bool, hash: &str) -> anyhow::Result<()> {
    let object = Object::from_hash(hash)?;
    let content = object.content()?;
    to_stdout(content.to_string())?;
    Ok(())
}
