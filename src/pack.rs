use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
};

use flate2::read::ZlibDecoder;
use nom::{bytes::complete::take, error::Error, error::ErrorKind, number::complete::u8, IResult};
use std::io::Read;

use crate::object::{Object, ObjectType};

#[derive(Clone, Debug, PartialEq)]
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

pub enum PackDelta {
    Insert(Vec<u8>),
    Copy { offset: u64, size: u64 },
}

#[derive(Clone, Debug)]
pub enum DeltaInfo {
    Offset(usize),    // backward distance in bytes to base object
    RefHash(Vec<u8>), // 20‑ or 32‑byte hash
}

#[derive(Debug)]
pub struct PackEntry<'a> {
    pub object_type: PackObjectType,
    pub size: u64,
    pub delta_info: Option<DeltaInfo>,
    /// points at the start of the zlib‑compressed payload
    pub payload: &'a [u8],
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

/// Decode a single Git pack varint byte.
/// Returns (value_of_this_byte, continuation_flag).
fn git_delta_command(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
    let (rest, b) = u8(input)?;
    // MSB = command
    let command = b >> 7;
    // lower 7 bits hold offset bits or length
    let offset_or_length = b & 0x7F;
    Ok((rest, (offset_or_length, command)))
}

/// Decode a single Git pack varint byte.
/// Returns (value_of_this_byte, continuation_flag).
fn git_varint_byte(input: &[u8]) -> IResult<&[u8], (u8, bool)> {
    // Grab one raw byte
    let (rest, b) = u8(input)?;
    // MSB = continuation flag
    let cont = (b & 0x80) != 0;
    // Lower 7 bits hold payload
    let payload = b & 0x7F;
    Ok((rest, (payload, cont)))
}

/// Parse a full variable‑length integer.
///
/// Git pack offsets are limited to five bytes (max 2³⁵‑1).  
/// The generic version below accepts any number of bytes, but we stop after 5 to stay within the spec.
pub fn git_varint(input: &[u8]) -> IResult<&[u8], u64> {
    // Accumulate payload bytes until we hit a byte whose MSB == 0.
    // We also enforce a maximum of 5 bytes to avoid infinite loops on malformed data.
    let mut acc: u64 = 0;
    let mut shift = 0usize;
    let mut remaining = input;

    // enforces the maximum of five bytes that the Git pack‑file specification permits for a varint.
    for _i in 0..5 {
        let (rest, (payload, cont)) = git_varint_byte(remaining)?;
        // Incorporate the 7‑bit chunk.
        acc |= (payload as u64) << shift;
        shift += 7;

        remaining = rest;
        if !cont {
            // Last byte reached – success.
            return Ok((remaining, acc));
        }
    }

    // If we exit the loop we have read 5 bytes and still see a continuation flag.
    // According to the spec this is invalid, so we return an error.
    Err(nom::Err::Error(nom::error::Error::new(
        remaining,
        ErrorKind::TooLarge,
    )))
}

fn parse_ofs_delta_offset(input: &[u8]) -> IResult<&[u8], u64> {
    // offset encoding:
    // n bytes with MSB set in all but the last one.
    // The offset is then the number constructed by
    // concatenating the lower 7 bit of each byte, and
    // for n >= 2 adding 2^7 + 2^14 + ... + 2^(7*(n-1))
    // to the result.
    let (mut rest, (first_payload, first_cont)) = git_varint_byte(input)?;

    // The first payload contributes the high‑order bits *without* a left‑shift.
    // (Git’s spec says the first byte’s 7 bits are the most‑significant part.)
    let mut offset: u64 = first_payload as u64;
    let mut cont = first_cont;

    while cont {
        let (new_rest, (payload, more)) = git_varint_byte(rest)?;
        offset = (offset << 7) | (payload as u64);
        rest = new_rest;
        cont = more;
    }

    Ok((rest, offset))
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

/// Parse the *entire* pack‑object header (type + full size) and return the
/// remaining slice together with the extracted information.
pub fn parse_object_header(input: &[u8]) -> IResult<&[u8], (PackObjectType, u64)> {
    let (mut rest, (first_payload, first_cont)) = git_varint_byte(input)?;

    // Bits 6‑4 of the original byte are the object type.
    let type_bits = (first_payload >> 4) & 0b111;
    let obj_type: PackObjectType = type_bits.try_into().expect("valid object type");

    // Bits 3‑0 are the low three size bits.
    let mut size: u64 = (first_payload & 0b1111) as u64;
    let mut shift = 4;

    // TODO should check that we only parse 4 additional bytes
    let mut cont = first_cont;
    while cont {
        let (new_rest, (payload, more)) = git_varint_byte(rest)?;
        size |= (payload as u64) << shift;
        shift += 7;
        rest = new_rest;
        cont = more;
    }

    Ok((rest, (obj_type, size)))
}

fn handle_delta(input: &[u8]) -> IResult<&[u8], Vec<PackDelta>> {
    let mut deltas: Vec<PackDelta> = Vec::new();
    let mut rest_decompressed = input;
    while !rest_decompressed.is_empty() {
        let (r, (offset_or_len, command)) = git_delta_command(rest_decompressed)?;

        if command == 0 {
            // insert command
            // +----------+============+
            // | 0xxxxxxx |    data    |
            // +----------+============+

            let len = offset_or_len as usize;
            println!(
                "append: {len} bytes to read and total remaining = {}",
                r.len()
            );
            let (r, new_data) = take(len)(r)?;

            deltas.push(PackDelta::Insert(new_data.to_owned()));

            rest_decompressed = r;
        } else if command == 1 {
            // copy command
            // +----------+---------+---------+---------+---------+-------+-------+-------+
            // | 1xxxxxxx | offset1 | offset2 | offset3 | offset4 | size1 | size2 | size3 |
            // +----------+---------+---------+---------+---------+-------+-------+-------+
            //
            // with the final offset and size values, copy size bytes from the
            // base object starting at position offset into your output buffer
            //
            // The copy command essentially says: "Take size bytes from the base object starting at
            // offset and append them to the reconstructed object."

            let offset_bits = offset_or_len;

            let mut offset: u64 = 0;
            let mut size: u64 = 0;
            let mut shift = 0;

            let mut r = r;
            for i in 0..4 {
                if (offset_bits & (1 << i)) != 0 {
                    let (new_rest, b) = nom::bytes::complete::take(1usize)(r)?;
                    offset |= (*b.first().unwrap() as u64) << shift;
                    r = new_rest;
                }
                // always shift even if this bit is not set
                shift += 8;
            }

            shift = 0;
            for i in 4..7 {
                if (offset_bits & (1 << i)) != 0 {
                    let (new_rest, b) = nom::bytes::complete::take(1usize)(r)?;
                    size |= (*b.first().unwrap() as u64) << shift;
                    r = new_rest;
                }
                // always shift even if this bit is not set
                shift += 8;
            }

            // default size if none of the size flags were set.
            if size == 0 {
                size = 0x10000;
            }

            let bytes_consumed = offset_bits.count_ones() as u64;

            println!(
                "copy  : {bytes_consumed} bytes to read and total remaining = {}. offset = {offset}",
                r.len()
            );

            deltas.push(PackDelta::Copy { offset, size });

            rest_decompressed = r;
        } else {
            panic!("unknown command in delta encoding");
        };
    }

    Ok((rest_decompressed, deltas))
}

pub(crate) fn parse_object<'a>(
    object_type: PackObjectType,
    uncompressed_length: u64,
    input: &'a [u8],
) -> (&'a [u8], PackEntry<'a>) {
    let mut rest = input;
    let mut delta_info = None;
    match object_type {
        PackObjectType::Commit | PackObjectType::Tree | PackObjectType::Blob => {}
        PackObjectType::OffsetDelta => {
            let (new_rest, base_obj_offset) = parse_ofs_delta_offset(rest).unwrap();
            rest = new_rest;
            delta_info = Some(DeltaInfo::Offset(base_obj_offset as usize));
        }
        PackObjectType::ReferenceDelta => {
            // TODO correct version handling
            // 2 | 3 => 20 bytes SHA‑1
            // 4     => 32 bytes SHA‑256 (v4 packs)
            let base_sha = &rest[..20];
            rest = &rest[20..];
            delta_info = Some(DeltaInfo::RefHash(base_sha.to_owned()));
        }
    }

    let payload = &rest;
    let mut z = ZlibDecoder::new(rest);
    let mut data = vec![0u8; uncompressed_length as usize];
    z.read_exact(&mut data).unwrap();

    // all this just to understand how much data we need to read from rest?
    // maybe just as easy to keep the decompressed bytes?
    let compressed_size = z.total_in() as usize;

    let entry = PackEntry {
        object_type,
        size: uncompressed_length,
        delta_info,
        payload,
    };

    // NOTE: uncompressed_length can be 0 (zero-sized blobs)
    // this implementation handles this case
    if compressed_size == 0 {
        // TODO why? just tested with trial and error? always the same?
        // empty data gets the zlib header (2 bytes) + compressed empty block (1 byte) +
        // Adler-32 checksum (4 bytes) + potential padding = ~8 bytes total?
        (&rest[compressed_size + 8..], entry)
    } else {
        (&rest[compressed_size..], entry)
    }
}

fn base_from<'a>(
    pack_objects: &BTreeMap<usize, PackEntry<'a>>,
    offset: &usize,
    base: DeltaInfo,
    offset_type: &HashMap<usize, ObjectType>,
) -> (ObjectType, Vec<u8>) {
    // TODO we need recursion to resolve this
    match base {
        DeltaInfo::Offset(delta) => {
            // FIXME why correction? same for all runs?
            let offset = offset.checked_sub(delta + 128).unwrap();
            let entry = pack_objects.get(&offset).unwrap();
            let ot = offset_type.get(&offset).unwrap();

            let mut z = ZlibDecoder::new(entry.payload);
            let mut data = vec![0u8; entry.size as usize];
            z.read_exact(&mut data).unwrap();

            (ot.clone(), data)
        }
        DeltaInfo::RefHash(base_sha) => {
            // TODO here we assume it has already written to the .git folder
            // we can also reconstruct it again from the pack objects but need a mapping for the
            // hash
            let base_object = match Object::from_hash(hex::encode(base_sha.clone()).as_str()) {
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

            (base_object.object_type, object_data)
        }
    }
}

pub(crate) fn reconstruct_objects<'a>(pack_objects: &BTreeMap<usize, PackEntry<'a>>) {
    let mut offset_type: HashMap<usize, ObjectType> = HashMap::new();
    for (offset, entry) in pack_objects {
        let mut z = ZlibDecoder::new(entry.payload);
        let mut data = vec![0u8; entry.size as usize];
        z.read_exact(&mut data).unwrap();

        let object = match &entry.object_type {
            pot @ (PackObjectType::Commit | PackObjectType::Tree | PackObjectType::Blob) => {
                offset_type.insert(*offset, pot.clone().into());
                Object::from_pack(pot.clone().into(), &data)
            }
            PackObjectType::OffsetDelta | PackObjectType::ReferenceDelta => {
                let (ot, base) = base_from(
                    pack_objects,
                    offset,
                    entry.delta_info.clone().unwrap(),
                    &offset_type,
                );
                offset_type.insert(*offset, ot.clone());

                // source size (variable-length encoded) should match the size of the base object
                // this probably does not include the header of the binary on disk?
                let (r, _src_size) = git_varint(&data).unwrap();
                // assert!(base_object.size as u64 == src_size);

                // target size (variable-length encoded) should validate the final object size
                let (r, _target_size) = git_varint(r).unwrap();

                let (_, deltas) = handle_delta(r).unwrap();
                Object::from_pack_deltas(&base, &deltas, ot)

                // assert!(final_obj.size == target_size);
            }
        };

        // TODO maybe we dont want to write this out?
        object.write().unwrap();

        // verbose
        println!(
            "{} {} {} {} {offset}",
            object.hash_str(),
            object.object_type,
            entry.size,
            object.compressed.len(),
            // TODO I dont understand how to compute this length? does it include the header?
            // and what does object.size actually contain? the compressed size without the
            // header?
            // 2 + object.compressed.len() + format!("{ot} {}\0", object.size).len(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a u64 into the Git varint representation (max 5 bytes).
    pub fn encode_git_varint(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (n & 0x7F) as u8;
            n >>= 7;
            if n != 0 {
                // More bytes to come – set continuation flag.
                byte |= 0x80;
            }
            out.push(byte);
            if n == 0 {
                break;
            }
        }
        out
    }

    #[test]
    fn roundtrip_small_numbers() {
        for v in 0u64..=0xFFFF {
            let enc = encode_git_varint(v);
            let (_, dec) = git_varint(&enc).expect("should parse");
            assert_eq!(v, dec, "failed for {}", v);
        }
    }

    #[test]
    fn max_allowed_value() {
        // 5 bytes => 35 bits => max = 2^35 - 1
        let max = (1u64 << 35) - 1;
        let enc = encode_git_varint(max);
        assert_eq!(enc.len(), 5);
        let (_, dec) = git_varint(&enc).unwrap();
        assert_eq!(dec, max);
    }

    #[test]
    fn reject_too_long() {
        // 6‑byte encoding should be rejected.
        let mut bad = encode_git_varint((1u64 << 35) - 1);
        // Force continuation on the last byte to make it look like a 6‑byte value.
        let last = *bad.last_mut().unwrap();
        *bad.last_mut().unwrap() = last | 0x80;
        // Append a dummy continuation byte.
        bad.push(0x01);
        assert!(git_varint(&bad).is_err());
    }

    #[test]
    fn basic_commit_one_byte_size() {
        // Header: 0b1100_0010
        //  - bits7‑6 = 11 (always)
        //  - bit6 (cont) = 1 → more size bytes follow (we’ll add one)
        //  - type = 001 (commit)
        //  - low size = 010 (2)
        // Next size byte: 0b0000_0001 (cont=0, payload=1) → adds 1<<3 = 8
        let data = [0b1100_0010, 0b0000_0001];
        let (_, (typ, sz)) = parse_object_header(&data).unwrap();
        assert_eq!(typ, PackObjectType::Commit);
        assert_eq!(sz, 10); // 2 (low) + 8 (extra) = 10
    }

    #[test]
    fn blob_no_continuation() {
        // 0b1000_0111
        //  - type = 011 (blob)
        //  - low size = 111 (7)
        //  - cont = 0 (no extra bytes)
        let data = [0b1000_0111];
        let (_, (typ, sz)) = parse_object_header(&data).unwrap();
        assert_eq!(typ, PackObjectType::Blob);
        assert_eq!(sz, 7);
    }

    #[test]
    fn ofs_delta_multi_byte_size() {
        // First byte: 0b1011_0010
        //  - type = 101 (OFS_DELTA)
        //  - low size = 010 (2)
        //  - cont = 1 (more)
        // Next bytes: 0b1000_0011 (cont=1, payload=3) → adds 3 << 3 = 24
        //             0b0000_0100 (cont=0, payload=4) → adds 4 << 10 = 4096
        let data = [0b1011_0010, 0b1000_0011, 0b0000_0100];
        let (_, (typ, sz)) = parse_object_header(&data).unwrap();
        assert_eq!(typ, PackObjectType::OffsetDelta);
        // size = 2 + (3 << 3) + (4 << 10) = 2 + 24 + 4096 = 4122
        assert_eq!(sz, 4122);
    }
}
