use std::{
    collections::BTreeMap,
    io::{BufReader, Read},
};

use crate::pack::{self, PackEntry};

pub(crate) fn invoke(pack_file: &str, verbose: bool) -> anyhow::Result<()> {
    let file = std::fs::File::open(pack_file)?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new();
    let _read_size = reader.read_to_end(&mut data)?;

    let mut offset = 0;
    let (rest, (version, num_objects)) =
        pack::parse_header(&data).map_err(|e| anyhow::anyhow!("Failed to parse pack: {:?}", e))?;
    assert!(version == 2);
    offset += data.len() - rest.len();

    let mut pack_objects: BTreeMap<usize, PackEntry> = BTreeMap::new();
    let mut rest = rest;
    for _ in 0..num_objects {
        let (new_rest, (object_type, length)) = pack::parse_object_header(rest)
            .map_err(|e| anyhow::anyhow!("Failed to parse pack object header: {:?}", e))?;
        let (new_rest, entry) = pack::parse_object(object_type, length, new_rest);
        pack_objects.insert(offset, entry);

        offset += rest.len() - new_rest.len();
        rest = new_rest;
    }

    // reconstruct objects
    pack::reconstruct_objects(&pack_objects, verbose);

    // for (offset, entry) in pack_objects {
    //     match entry.object_type {
    //         pot @ (PackObjectType::Commit | PackObjectType::Tree | PackObjectType::Blob) => {
    //             println!(
    //                 "{} {} {uncompressed_length} {} {offset}",
    //                 object.hash_str(),
    //                 ot,
    //                 object.compressed.len(),
    //                 // TODO I dont understand how to compute this length? does it include the header?
    //                 // and what does object.size actually contain? the compressed size without the
    //                 // header?
    //                 // 2 + object.compressed.len() + format!("{ot} {}\0", object.size).len(),
    //             );
    //         }
    //         PackObjectType::OffsetDelta => {
    //             println!(
    //                 "{} {} {uncompressed_length} {} {offset}",
    //                 object.hash_str(),
    //                 ot,
    //                 compressed_size + 20 + 2,
    //             );
    //         }
    //         PackObjectType::ReferenceDelta => {
    //             println!(
    //                 "{} {} {uncompressed_length} {} {offset} {}",
    //                 object.hash_str(),
    //                 ot,
    //                 compressed_size + 20 + 2,
    //                 hex::encode(base_sha)
    //             );
    //         }
    //     }
    // }

    // TODO parse crc and check

    Ok(())
}
