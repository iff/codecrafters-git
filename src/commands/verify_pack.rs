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
    assert!(version == 2);
    offset += data.len() - rest.len();

    let mut rest = rest;
    for _ in 0..num_objects {
        let (new_rest, (object_type, length)) = pack::parse_object_header(rest)
            .map_err(|e| anyhow::anyhow!("Failed to parse pack object header: {:?}", e))?;

        let new_rest = pack::parse_object(&data, object_type, length, new_rest, offset);
        offset += rest.len() - new_rest.len();
        rest = new_rest;
    }

    // TODO parse crc and check

    Ok(())
}
