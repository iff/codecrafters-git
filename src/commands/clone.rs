// Working with the git-pack web service to get the pack file
// Decoding the pack file format (work in byte strings or else you'd split your hairs trying to find offset errors, note that offset are based on length of compressed data)
// Working with git-delta objects
//
// The best reference I found was the book building git by James Coglan. Good luck to anyone attempting this, it's gonna take a few days the very least so be patient.
//
// checkout-empty <commit>
// unpack-objects (undeltified)
// unpack-objects (REF_DELTA)
// ls-remote <url> HEAD
// clone <url> <dir>

pub(crate) fn invoke(url: &str, path: Option<String>) -> anyhow::Result<()> {
    let response = reqwest::blocking::get(format!("{url}/info/refs?service=git-upload-pack"))?;
    let body = response.text()?;
    // first line: Clients MUST validate the first five bytes of the response entity matches the regex ^[0-9a-f]{4}#. If this test fails, clients MUST NOT continue.
    // parse 001e#
    // then 00000159SHA HEAD...
    // then all refs
    // end with 0000
    println!("{}", body);
    Ok(())
}
