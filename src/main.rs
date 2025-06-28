#[allow(unused_imports)]
use std::env;
use std::ffi::CString;
#[allow(unused_imports)]
use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;

use flate2::read::ZlibDecoder;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    eprintln!("Logs from your program will appear here!");

    let args: Vec<String> = env::args().collect();
    if args[1] == "init" {
        fs::create_dir(".git").unwrap();
        fs::create_dir(".git/objects").unwrap();
        fs::create_dir(".git/refs").unwrap();
        fs::write(".git/HEAD", "ref: refs/heads/main\n").unwrap();
        println!("Initialized git directory")
    } else if args[1] == "cat-file" {
        // args: -p <blob_sha>
        // TODO commands
        assert!(args[2] == "-p");

        // read file .git/objects/2chars/rest
        let hash = &args[3];
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
            return;
        };
        // TODO check that we get a 'blob'
        // TODO match
        assert!(blob_type == "blob");

        let size = size.parse::<u64>().expect("parsable size");
        let mut content = Vec::new();
        r.take(size)
            .read_to_end(&mut content)
            .expect("reading content of size");
        let content = str::from_utf8(content.as_slice()).expect("content is string");
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        write!(stdout, "{}", content).expect("writing to stdout");
    } else {
        println!("unknown command: {}", args[1])
    }
}
