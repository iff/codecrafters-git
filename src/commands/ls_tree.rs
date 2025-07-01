use crate::object::to_stdout;
use crate::object::Object;

pub(crate) fn invoke(name_only: bool, hash: &str) -> anyhow::Result<()> {
    let object = Object::from_hash(hash)?;
    // TODO sort
    let content = object.tree_content()?;
    if name_only {
        to_stdout(
            content
                .iter()
                .map(|t| t.name.clone())
                .collect::<Vec<String>>()
                .join("\n"),
        )?;
        to_stdout("\n".to_string())?;
    } else {
        to_stdout(
            content
                .iter()
                .map(|t| {
                    // FIXME object type
                    // FIXME sha
                    format!(
                        "{} blob {}\t{}",
                        t.mode,
                        String::from("sha"),
                        t.name.clone()
                    )
                })
                .collect::<Vec<String>>()
                .join("\n"),
        )?;
    }
    Ok(())
}
