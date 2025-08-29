use std::io::{BufReader, Read};

use crate::pack;

pub(crate) fn invoke(pack_file: &str) -> anyhow::Result<()> {
    let file = std::fs::File::open(pack_file)?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new();
    let _read_size = reader.read_to_end(&mut data)?;

    let mut offset = 0;
    let (rest, (version, num_objects)) =
        pack::parse_header(&data).map_err(|e| anyhow::anyhow!("Failed to parse pack: {:?}", e))?;
    offset += data.len() - rest.len();

    assert!(version == 2);
    println!("pack: {} objects recieved", num_objects);

    let mut rest = rest;
    for _ in 0..num_objects {
        let before = rest.len();
        let (new_rest, (object_type, length)) = pack::parse_object_header(rest)
            .map_err(|e| anyhow::anyhow!("Failed to parse pack: {:?}", e))?;

        let new_rest = pack::parse_object(object_type, length, new_rest, offset);
        offset += before - new_rest.len();
        rest = new_rest;
    }

    Ok(())
}
