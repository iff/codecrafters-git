use std::io::{BufReader, Read};

use crate::pack;

pub(crate) fn invoke(pack_file: &str) -> anyhow::Result<()> {
    let file = std::fs::File::open(pack_file)?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new();
    let read_size = reader.read_to_end(&mut data)?;

    let (rest, (version, num_objects)) =
        pack::parse_header(&data).map_err(|e| anyhow::anyhow!("Failed to parse pack: {:?}", e))?;

    // TODO for now?
    assert!(version == 2);
    println!("pack: {} objects recieved", num_objects);

    let mut rest = rest;
    // just to mimic the output of git verify-pack as debug help
    let mut offset = 12;
    for _ in 0..num_objects {
        let before = rest.len();
        let (new_rest, (object_type, length)) = pack::parse_object_header(rest)
            .map_err(|e| anyhow::anyhow!("Failed to parse pack: {:?}", e))?;
        println!("{object_type}, {length}");
        // TODO can be one?
        // assert_eq!(2, before - new_rest.len());

        let new_rest = pack::parse_object(object_type, length, new_rest, offset);
        println!("object parsed {} bytes", before - new_rest.len());
        offset += before - new_rest.len();
        rest = new_rest;
    }

    Ok(())
}
