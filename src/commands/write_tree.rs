use crate::object::to_stdout;

pub(crate) fn invoke() -> anyhow::Result<()> {
    to_stdout("\n".to_string())?;
    Ok(())
}
