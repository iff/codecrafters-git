use std::{
    fmt::Display,
    io::{BufReader, Write},
};

use flate2::read::ZlibDecoder;
use nom::{bytes::complete::take, error::Error, IResult};
use std::io::Read;

use crate::object::{GitObjectWriter, Object, ObjectType};

pub(crate) enum PackObjectType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    OffsetDelta = 6,
    ReferenceDelta = 7,
}

impl Display for PackObjectType {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            PackObjectType::Commit => write!(fmt, "Commit")?,
            PackObjectType::Tree => write!(fmt, "Tree")?,
            PackObjectType::Blob => write!(fmt, "Blob")?,
            PackObjectType::OffsetDelta => write!(fmt, "OffsetDelta")?,
            PackObjectType::ReferenceDelta => write!(fmt, "ReferenceDelta")?,
        }
        Ok(())
    }
}

impl TryFrom<u8> for PackObjectType {
    // FIXME need a cleaner error type here
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PackObjectType::Commit),
            2 => Ok(PackObjectType::Tree),
            3 => Ok(PackObjectType::Blob),
            6 => Ok(PackObjectType::OffsetDelta),
            7 => Ok(PackObjectType::ReferenceDelta),
            _ => Err("unknown pack object type"),
        }
    }
}

fn u32_from_be_bytes(data: &[u8]) -> u32 {
    let data: [u8; 4] = data.try_into().expect("data expected to be 4 bytes");
    u32::from_be_bytes(data)
}

#[allow(dead_code)]
fn pkt_line(data: &str) -> Vec<u8> {
    let len = data.len() + 4; // +4 for the length prefix itself
    let mut packet = format!("{:04x}", len).into_bytes();
    packet.extend_from_slice(data.as_bytes());
    packet
}

fn read_pkt_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    // NOTE the length is encoded as ASCII hex characters and not binary
    // I guess it makes it more readable when debugging and sidesteps endianness issue?
    // still need to find a better way to write this
    let (rest, len) = take(4u8)(input)?;
    let len = u16::from_str_radix(std::str::from_utf8(len).unwrap(), 16).unwrap();
    take(len - 4)(rest)
}

pub(crate) fn parse_network_header(input: &[u8]) -> IResult<&[u8], (), Error<&[u8]>> {
    // TODO this is different when reading pack file from disk and what we get with http post
    // (cloning)?
    let (rest, pack_file) = read_pkt_line(input)?;
    assert!(pack_file == "packfile\n".as_bytes());

    // TODO? not sure what this actually is?
    // [50, 48, 48, 52, 1]
    let (rest, _unclear) = take(5u8)(rest)?;
    // println!("{:?}", unclear);

    Ok((rest, ()))
}

pub(crate) fn parse_header(input: &[u8]) -> IResult<&[u8], (u32, u32), Error<&[u8]>> {
    let (rest, pack) = take(4u8)(input)?;
    assert!(pack == "PACK".as_bytes());

    let (rest, version) = take(4u8)(rest)?;
    let version = u32_from_be_bytes(version);

    let (rest, num_objects) = take(4u8)(rest)?;
    let num_objects = u32_from_be_bytes(num_objects);

    Ok((rest, (version, num_objects)))
}

pub(crate) fn parse_object_header(
    input: &[u8],
) -> IResult<&[u8], (PackObjectType, usize), Error<&[u8]>> {
    use nom::bits::bits;
    use nom::bits::complete::take as take_bits;

    // TODO combine with parse_var_len
    // error handling a bit cumbersom here
    bits::<_, _, Error<(&[u8], usize)>, Error<&[u8]>, _>(|input| {
        let (rest, cont): (_, u8) = take_bits(1u8)(input)?;
        let (rest, object_type): (_, u8) = take_bits(3u8)(rest)?;
        let (rest, size): (_, u8) = take_bits(4u8)(rest)?;
        let mut size = size as usize;

        let mut shift = 4;
        let mut cont = cont;
        let mut rest = rest;
        while cont == 1 {
            let (new_rest, new_cont): (_, u8) = take_bits(1u8)(rest)?;
            cont = new_cont;
            let (new_rest, size_bits): (_, u8) = take_bits(7u8)(new_rest)?;
            rest = new_rest;

            size |= (size_bits as usize) << shift;
            shift += 7;
        }
        assert!(cont == 0);

        let object_type: PackObjectType = object_type.try_into().expect("valid object type");
        Ok((rest, (object_type, size)))
    })(input)
}

pub(crate) fn parse_var_len(input: &[u8]) -> IResult<&[u8], usize, Error<&[u8]>> {
    use nom::bits::bits;
    use nom::bits::complete::take as take_bits;

    // error handling a bit cumbersom here
    bits::<_, _, Error<(&[u8], usize)>, Error<&[u8]>, _>(|input| {
        let (rest, cont): (_, u8) = take_bits(1u8)(input)?;
        let (rest, size): (_, u8) = take_bits(7u8)(rest)?;
        let mut size = size as usize;

        let mut shift = 7;
        let mut cont = cont;
        let mut rest = rest;
        while cont == 1 {
            let (new_rest, new_cont): (_, u8) = take_bits(1u8)(rest)?;
            cont = new_cont;
            let (new_rest, size_bits): (_, u8) = take_bits(7u8)(new_rest)?;
            rest = new_rest;

            size |= (size_bits as usize) << shift;
            shift += 7;
        }
        assert!(cont == 0);

        Ok((rest, size))
    })(input)
}

pub(crate) fn parse_object(
    object_type: PackObjectType,
    uncompressed_length: usize,
    input: &[u8],
    offset: usize, // TODO: remove, only debug output
) -> &[u8] {
    let mut rest = input;
    match object_type {
        pot @ (PackObjectType::Commit | PackObjectType::Tree | PackObjectType::Blob) => {
            // NOTE: uncompressed_length can be 0 (zero-sized blobs)
            // this implementation handles this case
            let mut z = ZlibDecoder::new(rest);
            let mut data = vec![0u8; uncompressed_length];
            z.read_exact(&mut data).unwrap();

            let compressed_size = z.total_in() as usize;
            let ot: ObjectType = pot.into();
            let object = Object::from_pack(&ot, &data);
            object.write().unwrap();

            // debug output matching 'git verify-pack --verbose'
            println!(
                "{} {} {uncompressed_length} {} {offset}",
                object.hash_str(),
                ot,
                object.compressed.len(),
                // TODO I dont understand how to compute this length? does it include the header?
                // and what does object.size actually contain? the compressed size without the
                // header?
                // 2 + object.compressed.len() + format!("{ot} {}\0", object.size).len(),
            );

            if compressed_size == 0 {
                // TODO why? just tested with trial and error? always the same?
                // empty data gets the zlib header (2 bytes) + compressed empty block (1 byte) +
                // Adler-32 checksum (4 bytes) + potential padding = ~8 bytes total?
                &rest[compressed_size + 8..]
            } else {
                &rest[compressed_size..]
            }
        }
        PackObjectType::OffsetDelta => {
            panic!("not implemented");
        }
        PackObjectType::ReferenceDelta => {
            let base_sha = &rest[..20];

            let base_object = match Object::from_hash(hex::encode(base_sha).as_str()) {
                Ok(obj) => obj,
                Err(_e) => {
                    println!("{}", hex::encode(base_sha));
                    panic!("cant crate object from hash. hash does not exist?");
                }
            };
            let compressed = base_object.compressed;
            let mut z = ZlibDecoder::new(&compressed[..]);
            let mut object_data = Vec::new();
            z.read_to_end(&mut object_data).unwrap();

            // advance rest pointer
            rest = &rest[20..];

            println!("{}", hex::encode(base_sha));
            let mut z = ZlibDecoder::new(rest);
            let mut data = vec![0u8; uncompressed_length];
            z.read_exact(&mut data).unwrap();

            // source size (variable-length encoded) should match the size of the base object
            // this probably does not include the header of the binary on disk?
            let (r, src_size) = parse_var_len(&data).unwrap();
            assert!(base_object.size == src_size);

            // target size (variable-length encoded) should validate the final object size
            let (r, target_size) = parse_var_len(r).unwrap();

            // parse delta instructions (copy/insert commands)
            let mut rest_decompressed = r;
            while !rest_decompressed.is_empty() {
                use nom::bits::bits;
                use nom::bits::complete::take as take_bits;
                let (r, (command, offset_or_len)) =
                    bits::<_, _, Error<(&[u8], usize)>, Error<&[u8]>, _>(|input| {
                        let (rest, command): (_, u8) = take_bits(1u8)(input)?;
                        let (rest, offset_or_len): (_, u8) = take_bits(7u8)(rest)?;
                        Ok((rest, (command, offset_or_len)))
                    })(rest_decompressed)
                    .unwrap();

                if command == 0 {
                    // +----------+============+
                    // | 0xxxxxxx |    data    |
                    // +----------+============+
                    let len = offset_or_len as usize;
                    println!(
                        "append command: len = {len} and total remaining = {}",
                        rest_decompressed.len()
                    );
                    let _new_data = &r[..len];
                    rest_decompressed = &r[len..];

                    // TODO actually insert data
                    // data.extend(new_data);
                } else if command == 1 {
                    let offset_bits = offset_or_len;
                    // so size can be 3 bytes and offset 4 bytes
                    // and if we ommit size 1 we assume that size3 encodes bits 16..32 even
                    // when offset 2 is ommitted.
                    // +----------+---------+---------+---------+---------+-------+-------+-------+
                    // | 1xxxxxxx | offset1 | offset2 | offset3 | offset4 | size1 | size2 | size3 |
                    // +----------+---------+---------+---------+---------+-------+-------+-------+
                    //  Offset reconstruction (up to 4 bytes):
                    // - If bit 0 set: read offset byte 0 (least significant)
                    // - If bit 1 set: read offset byte 1
                    // - If bit 2 set: read offset byte 2
                    // - If bit 3 set: read offset byte 3 (most significant)
                    //
                    // Size reconstruction (up to 3 bytes):
                    // - If bit 4 set: read size byte 0 (least significant)
                    // - If bit 5 set: read size byte 1
                    // - If bit 6 set: read size byte 2 (most significant)
                    //
                    // Example: Command byte 0x91 (10010001)
                    // - Read 1 offset byte → offset = that byte value
                    // - Read 1 size byte → size = that byte value
                    // - Copy size bytes from base object starting at offset
                    //
                    // Usage: Once you have the final offset and size values, you copy size bytes from the
                    // base object starting at position offset into your output buffer.
                    //
                    // The copy command essentially says: "Take size bytes from the base object starting at
                    // offset and append them to the reconstructed object."

                    let num_bytes = offset_bits.count_ones() as usize;
                    println!(
                        "copy command: {:08b}, {} bytes to read and total remaining = {}",
                        offset_bits,
                        num_bytes,
                        rest_decompressed.len()
                    );

                    let new_data = &r[..num_bytes];
                    // TODO actually get offset and size and copy data
                    // just continuing for now

                    rest_decompressed = &r[num_bytes..];
                } else {
                    panic!("unknown command in delta encoding");
                };
            }

            let buf = Vec::new();
            let mut writer = GitObjectWriter::new(buf);
            writer.write_all(&data).unwrap();
            let (_compressed, hash) = writer.finish().unwrap();
            // TODO same type as base?
            // let final_obj = Object::new_commit(uncompressed_length, hash, &compressed);
            // final_obj.write().unwrap();
            // assert!(final_obj.size == target_size);

            let sha = hex::encode(hash);

            let compressed_size = z.total_in() as usize;
            println!(
                "{sha} commit {uncompressed_length} {} {offset} {}",
                compressed_size + 20 + 2,
                hex::encode(base_sha)
            );
            &rest[compressed_size..]
        }
    }
}
