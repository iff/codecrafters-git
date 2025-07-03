use crate::object::to_stdout;
use crate::object::Object;
use crate::object::ObjectType;
use crate::object::TreeObject;

pub(crate) fn invoke(name_only: bool, hash: &str) -> anyhow::Result<()> {
    let object = Object::from_hash(hash)?;
    let tree = TreeObject::read(&object)?;
    if name_only {
        to_stdout(
            tree.iter()
                .map(|t| t.name.clone())
                .collect::<Vec<String>>()
                .join("\n"),
        )?;
    } else {
        to_stdout(
            tree.iter()
                .map(|t| {
                    let ot = ObjectType::Tree;
                    format!(
                        "{} {} {}\t{}",
                        t.mode,
                        ot,
                        hex::encode(t.sha_bytes),
                        t.name.clone()
                    )
                })
                .collect::<Vec<String>>()
                .join("\n"),
        )?;
    }

    // FIXME why?
    to_stdout("\n".to_string())?;
    Ok(())
}
