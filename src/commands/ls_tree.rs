use crate::object::to_stdout;
use crate::object::Object;

pub(crate) fn invoke(name_only: bool, hash: &str) -> anyhow::Result<()> {
    let object = Object::from_hash(hash)?;
    let content = object.tree_content()?;
    if name_only {
        to_stdout(
            content
                .iter()
                .map(|t| t.name.clone())
                .collect::<Vec<String>>()
                .join("\n"),
        )?;
    } else {
        to_stdout(
            content
                .iter()
                .map(|t| {
                    // FIXME object type
                    format!(
                        "{} blob {}\t{}",
                        t.mode,
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
