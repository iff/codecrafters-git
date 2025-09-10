//! Implements helpers and data structures to read Git pack files.
//!
//! # Limitations
//! - only supports version 2
//! - no writing support, only reading
//! - limited tests
//!
//! # Docs
//! - [git pack format](https://git-scm.com/docs/gitformat-pack)
use std::{collections::BTreeMap, fmt::Display};

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

enum PackDelta {
    Insert(Vec<u8>),
    Copy { offset: u64, size: u64 },
}

enum PackEntryType {
    Commit,
    Tree,
    Blob,
    OffsetDelta(usize),      // backward distance in bytes to base object
    ReferenceDelta(Vec<u8>), // 20‑ or 32‑byte hash (depends on git version)
}

/// Holds all the data we need to reconstruct an object in a second pass (see
/// [`reconstruct_objects`]).
pub struct PackEntry<'a> {
    object_type: PackEntryType,
    size: u64,
    /// points at the start of the zlib‑compressed payload
    payload: &'a [u8],
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

pub fn read_pkt_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    // NOTE the length is encoded as ASCII hex characters and not binary
    // I guess it makes it more readable when debugging and sidesteps endianness issue?
    // still need to find a better way to write this
    let (rest, len) = take(4u8)(input)?;
    let len = u16::from_str_radix(std::str::from_utf8(len).unwrap(), 16).unwrap();
    take(len - 4)(rest)
}

/// delta commands are no shifted as varints
fn git_delta_command(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
    let (rest, b) = u8(input)?;
    let command = b >> 7;
    let offset_or_length = b & 0x7F;
    Ok((rest, (offset_or_length, command)))
}

/// decode a single Git pack varint byte
/// returns (value_of_this_byte, continuation_flag).
fn git_varint_byte(input: &[u8]) -> IResult<&[u8], (u8, bool)> {
    let (rest, b) = u8(input)?;
    // MSB = continuation flag
    let cont = (b & 0x80) != 0;
    let payload = b & 0x7F;
    Ok((rest, (payload, cont)))
}

/// parse a full variable‑length integer
///
/// Git pack offsets are limited to five bytes. We stop after 5 to stay within the spec.
pub fn git_varint(input: &[u8]) -> IResult<&[u8], u64> {
    let mut acc: u64 = 0;
    let mut shift = 0usize;
    let mut remaining = input;

    for _i in 0..5 {
        let (rest, (payload, cont)) = git_varint_byte(remaining)?;
        acc |= (payload as u64) << shift;
        shift += 7;

        remaining = rest;
        if !cont {
            return Ok((remaining, acc));
        }
    }

    // TODO not sure about this error?
    Err(nom::Err::Error(nom::error::Error::new(
        remaining,
        ErrorKind::TooLarge,
    )))
}

/// Parses the OBJ_OFS_DELTA offset:
///   - n bytes with MSB set in all but the last one
///   - the offset is then the number constructed by concatenating the lower 7 bit of each byte
///   - and for n >= 2, add the magic numbers: 2^7 + 2^14 + ... + 2^(7*(n-1))
///
/// # Returns
///
/// The returned offset is a negative relative offset from the delta object's position in the pack.
///
/// # Details
///
/// - [git pack format](https://git-scm.com/docs/gitformat-pack#_pack_pack_files_have_the_following_format)
/// - [offset encoding](https://git-scm.com/docs/gitformat-pack#_original_version_1_pack_idx_files_have_the_following_format)
fn parse_ofs_delta_offset(input: &[u8]) -> IResult<&[u8], u64> {
    let (mut rest, (first_payload, first_cont)) = git_varint_byte(input)?;
    let mut bytes_read = 1;

    let mut offset: u64 = first_payload as u64;
    let mut cont = first_cont;
    while cont {
        let (new_rest, (payload, more)) = git_varint_byte(rest)?;
        offset = (offset << 7) | (payload as u64);
        rest = new_rest;
        cont = more;
        bytes_read += 1;
    }

    // add the magic numbers
    if bytes_read >= 2 {
        for i in 1..bytes_read {
            offset += 1u64 << (7 * i);
        }
    }

    Ok((rest, offset))
}

/// Parse the *entire* pack header (version + number of objects).
/// Returns the remaining slice together with the extracted information.
pub(crate) fn parse_header(input: &[u8]) -> IResult<&[u8], (u32, u32), Error<&[u8]>> {
    let (rest, pack) = take(4u8)(input)?;
    assert!(pack == "PACK".as_bytes());

    let (rest, version) = take(4u8)(rest)?;
    let version = u32_from_be_bytes(version);

    let (rest, num_objects) = take(4u8)(rest)?;
    let num_objects = u32_from_be_bytes(num_objects);

    Ok((rest, (version, num_objects)))
}

/// Parse the *entire* pack‑object header (type + full size).
/// Returns the remaining slice together with the extracted information.
pub fn parse_object_header(input: &[u8]) -> IResult<&[u8], (PackObjectType, u64)> {
    let (mut rest, (first_payload, first_cont)) = git_varint_byte(input)?;

    // bits 6‑4 of the original byte are the object type.
    let type_bits = (first_payload >> 4) & 0b111;
    let obj_type: PackObjectType = type_bits.try_into().expect("valid object type");

    // bits 3‑0 are the low three size bits.
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

            deltas.push(PackDelta::Copy { offset, size });

            rest_decompressed = r;
        } else {
            panic!("unknown command in delta encoding");
        };
    }

    Ok((rest_decompressed, deltas))
}

/// Extracting a specific object type starting at `input` and returning the bytes after the object
/// and a [`PackEntry`] needed to reconstruct the object later.
/// Note that the `inflated_length` is the length of the data after decompression.
pub(crate) fn parse_object<'a>(
    object_type: PackObjectType,
    inflated_length: u64,
    input: &'a [u8],
) -> (&'a [u8], PackEntry<'a>) {
    let mut rest = input;
    let pet = match object_type {
        PackObjectType::Commit => PackEntryType::Commit,
        PackObjectType::Tree => PackEntryType::Tree,
        PackObjectType::Blob => PackEntryType::Blob,
        PackObjectType::OffsetDelta => {
            let (new_rest, base_obj_offset) = parse_ofs_delta_offset(rest).unwrap();
            rest = new_rest;
            PackEntryType::OffsetDelta(base_obj_offset as usize)
        }
        PackObjectType::ReferenceDelta => {
            // TODO correct version handling
            // 2 | 3 => 20 bytes SHA‑1
            // 4     => 32 bytes SHA‑256 (v4 packs)
            let base_sha = &rest[..20];
            rest = &rest[20..];
            PackEntryType::ReferenceDelta(base_sha.to_owned())
        }
    };

    let payload = &rest;
    let mut z = ZlibDecoder::new(rest);
    let mut data = vec![0u8; inflated_length as usize];
    z.read_exact(&mut data).unwrap();

    // all this just to understand how much data we need to read from rest?
    // maybe just as easy to keep the decompressed bytes?
    let compressed_size = z.total_in() as usize;

    let entry = PackEntry {
        object_type: pet,
        size: inflated_length,
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

/// Given a byte stream `base`, apply the delta operations.
/// Returns object bytes after applying operations.
fn apply_deltas(base: &[u8], deltas: &Vec<PackDelta>) -> Vec<u8> {
    let mut obj: Vec<u8> = Vec::new();
    for delta in deltas {
        match delta {
            PackDelta::Insert(data) => obj.extend_from_slice(data),
            PackDelta::Copy { offset, size } => {
                let offset = *offset as usize;
                let size = *size as usize;
                obj.extend_from_slice(&base[offset..offset + size]);
            }
        }
    }

    obj
}

/// Recursively reconstruct the object starting at `offset`. Apply operations to objects with delta compressions.
/// Returns its object type and bytes.
fn object_from<'a>(
    pack_objects: &BTreeMap<usize, PackEntry<'a>>,
    offset: usize,
) -> (ObjectType, Vec<u8>) {
    let object = pack_objects.get(&offset).unwrap();
    let mut z = ZlibDecoder::new(object.payload);
    let mut data = vec![0u8; object.size as usize];
    z.read_exact(&mut data).unwrap();

    match &object.object_type {
        PackEntryType::Commit => (ObjectType::Commit, data),
        PackEntryType::Tree => (ObjectType::Tree, data),
        PackEntryType::Blob => (ObjectType::Blob, data),
        PackEntryType::OffsetDelta(delta) => {
            let delta_offset = offset.checked_sub(*delta).unwrap();
            let (ot, obj) = object_from(pack_objects, delta_offset);

            let (r, src_size) = git_varint(&data).unwrap();
            assert!(obj.len() as u64 == src_size);
            let (r, target_size) = git_varint(r).unwrap();
            let (_, deltas) = handle_delta(r).unwrap();
            let obj = apply_deltas(&obj, &deltas);
            assert!(obj.len() as u64 == target_size);

            (ot, obj)
        }
        PackEntryType::ReferenceDelta(base_sha) => {
            // TODO dangerous assumption: assume referred sha was already written to the .git folder
            // TODO unless we keep a parallel list from sha to binary we can only go via fs atm
            let base_object = match Object::from_hash(hex::encode(base_sha.clone()).as_str()) {
                Ok(obj) => obj,
                Err(_e) => {
                    println!("ref hash with sha={}", hex::encode(base_sha));
                    panic!("failed to create object from sha: hash does not (yet) exists");
                }
            };
            let (_, content) = base_object.raw_content().unwrap();

            let (r, src_size) = git_varint(&data).unwrap();
            assert!(content.len() as u64 == src_size);
            let (r, target_size) = git_varint(r).unwrap();
            let (_, deltas) = handle_delta(r).unwrap();
            let obj = apply_deltas(&content, &deltas);
            assert!(obj.len() as u64 == target_size);

            (base_object.object_type, obj)
        }
    }
}

/// Given a mapping of offsets to pack entries, reconstruct the git objects and populate
/// `.git/objects` if `verify` is not set.
/// `verbose` mimics `git verify-pack --verbose`.
pub(crate) fn reconstruct_objects<'a>(
    pack_objects: &BTreeMap<usize, PackEntry<'a>>,
    verbose: bool,
    verify_only: bool,
) {
    for (offset, entry) in pack_objects {
        let (ot, data) = object_from(pack_objects, *offset);
        let object = Object::from_pack(ot, &data);

        if !verify_only {
            object.write().unwrap();
        }

        if verbose {
            println!(
                "{} {} {} {}? {offset}",
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
    fn blob_no_continuation() {
        //  - cont = 0 (no extra bytes)
        //  - type = 011 (blob)
        //  - low size = 111 (7)
        let data = [0b0011_0111];
        let (_, (typ, sz)) = parse_object_header(&data).unwrap();
        assert_eq!(typ, PackObjectType::Blob);
        assert_eq!(sz, 7);
    }

    #[test]
    fn test_single_byte_delta_offset() {
        // offset byte: 0x05 (continuation=0, payload=5)
        let offset_bytes = vec![0x05];
        let (_, base_start) = parse_ofs_delta_offset(&offset_bytes).unwrap();
        assert_eq!(base_start, 5);
    }

    #[test]
    fn test_multi_byte_delta_offset() {
        // We want an offset of 0x1234 = 4660 decimal.
        // Encode as base‑128 varint:
        //   0x1234 = 0b0001_0010_0011_0100
        //   Split into 7‑bit groups from the LSB:
        //     0b011_0100 = 0x34
        //     0b010_0010 = 0x24
        //   Emit high‑order group first, with continuation flag on all but last:
        //     first byte:  0x12 | 0x80 = 0xa4
        //     second byte: 0x34        = 0x34
        //
        // With magic numbers for 2-byte offset: 0x1234 + 2^7 = 4660 + 128 = 4788
        let offset_bytes = vec![0xa4, 0x34];
        let (_, base_start) = parse_ofs_delta_offset(&offset_bytes).unwrap();
        assert_eq!(base_start as usize, 0x1234 + 128);
    }
}
