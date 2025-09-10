use std::{
    collections::BTreeMap,
    io::{BufReader, Read},
};

use crate::pack::{self, PackEntry};

pub(crate) fn invoke(pack_file: &str, verbose: bool) -> anyhow::Result<()> {
    let file = std::fs::File::open(pack_file)?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;

    let mut offset = 0;
    let (rest, (version, num_objects)) =
        pack::parse_header(&data).map_err(|e| anyhow::anyhow!("failed to parse pack: {:?}", e))?;
    assert!(version == 2);
    offset += data.len() - rest.len();

    let mut pack_objects: BTreeMap<usize, PackEntry> = BTreeMap::new();
    let mut rest = rest;
    for _ in 0..num_objects {
        let (new_rest, (object_type, length)) = pack::parse_object_header(rest)
            .map_err(|e| anyhow::anyhow!("failed to parse pack object header: {:?}", e))?;
        let (new_rest, entry) = pack::parse_object(object_type, length, new_rest);
        pack_objects.insert(offset, entry);

        offset += rest.len() - new_rest.len();
        rest = new_rest;
    }

    // reconstruct objects
    pack::reconstruct_objects(&pack_objects, verbose, false);

    Ok(())
}
