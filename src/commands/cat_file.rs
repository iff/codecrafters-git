use std::ffi::CString;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;

use flate2::read::ZlibDecoder;

pub(crate) fn invoke(_pretty: bool, hash: &str) -> anyhow::Result<()> {
    let file = std::fs::File::open(format!(".git/objects/{}/{}", &hash[..2], &hash[2..]))
        .expect("object exists");

    let z = ZlibDecoder::new(file);
    let mut r = BufReader::new(z);

    // extract content: blob <size>\0<content>
    let mut header = Vec::new();
    r.read_until(0, &mut header).expect("0 in header");
    let content = String::from(
        CString::from_vec_with_nul(header)
            .expect("null terminated header")
            .to_str()
            .expect("convert to string"),
    );

    let Some((blob_type, size)) = content.split_once(' ') else {
        return Err(anyhow::Error::msg(format!("cant parse header {}", content)));
    };
    // TODO match later?
    assert!(blob_type == "blob");

    let size = size.parse::<u64>().expect("parsable size");
    let mut content = Vec::new();
    r.take(size)
        .read_to_end(&mut content)
        .expect("reading content of size");
    // TODO CString as well?
    let content = str::from_utf8(content.as_slice()).expect("content is string");
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    write!(stdout, "{}", content).expect("writing to stdout");

    Ok(())
}
