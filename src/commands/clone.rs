// Working with the git-pack web service to get the pack file
// Decoding the pack file format (work in byte strings or else you'd split your hairs trying to find offset errors, note that offset are based on length of compressed data)
// Working with git-delta objects
//
// The best reference I found was the book building git by James Coglan. Good luck to anyone attempting this, it's gonna take a few days the very least so be patient.
//
// checkout-empty <commit>
// unpack-objects (undeltified)
// unpack-objects (REF_DELTA)
// ls-remote <url> HEAD
// clone <url> <dir>

use std::{collections::HashSet, env, fs, io::Read};

use flate2::bufread::ZlibDecoder;
use nom::{
    bytes::complete::{is_not, tag, take, take_until},
    character::complete::char,
    combinator::not,
    multi::fold_many0,
    sequence::{delimited, preceded},
    IResult, Parser,
};
use reqwest::header;

use crate::commands::init;

struct RefSpec {
    #[allow(dead_code)]
    sha: String, // [u8; 40],
    #[allow(dead_code)]
    name: String,
}

struct Refs {
    head: String, //[u8; 40],
    // TODO what makes sense? see later
    #[allow(dead_code)]
    capabilities: HashSet<String>,
    // TODO Map name -> sha?
    #[allow(dead_code)]
    refs: Vec<RefSpec>,
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

mod pack {
    use std::{fmt::Display, io::Write};

    use nom::error::Error;

    use crate::object::{GitObjectWriter, Object};

    use super::*;

    pub(crate) enum PackObjectType {
        Commit = 1,
        Tree = 2,
        Blob = 3,
        OffsetDelta = 6,
        ReferenceDelta = 7,
    }

    impl Display for PackObjectType {
        fn fmt(
            &self,
            fmt: &mut std::fmt::Formatter<'_>,
        ) -> std::result::Result<(), std::fmt::Error> {
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

    pub(crate) fn parse_header(input: &[u8]) -> IResult<&[u8], (u32, u32), Error<&[u8]>> {
        let (rest, pack_file) = read_pkt_line(input)?;
        assert!(pack_file == "packfile\n".as_bytes());

        // TODO? not sure what this actually is?
        // [50, 48, 48, 52, 1]
        let (rest, _unclear) = take(5u8)(rest)?;
        // println!("{:?}", unclear);

        let (rest, pack) = take(4u8)(rest)?;
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
            // cont == 0 marks the end
            while cont == 1 {
                let (new_rest, new_cont): (_, u8) = take_bits(1u8)(rest)?;
                cont = new_cont;
                let (new_rest, size_bits): (_, u8) = take_bits(7u8)(new_rest)?;
                rest = new_rest;

                // TODO update size
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
            // cont == 0 marks the end
            while cont == 1 {
                let (new_rest, new_cont): (_, u8) = take_bits(1u8)(rest)?;
                cont = new_cont;
                let (new_rest, size_bits): (_, u8) = take_bits(7u8)(new_rest)?;
                rest = new_rest;

                // TODO update size
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
        offset: usize,
    ) -> &[u8] {
        // Output Format

        // SHA-1     type size  size-in-packfile offset-in-packfile [depth base-SHA-1]
        //
        // Column Breakdown
        //
        // 1. SHA-1: 40-character hex hash of the object
        // 2. type: Object type (commit, tree, blob, tag)
        // 3. size: Uncompressed size in bytes
        // 4. size-in-packfile: Compressed size in the pack file
        // 5. offset-in-packfile: Byte offset where object starts in pack
        // 6. depth (for deltas): How many delta links from base object
        // 7. base-SHA-1 (for deltas): SHA-1 of the base object

        let mut rest = input;
        match object_type {
            PackObjectType::Commit => {
                let restl = rest.len();
                // println!("{:08b}", rest[0]);
                // println!("{:08b}", rest[1]);
                let mut z = ZlibDecoder::new(rest);
                // let mut data = vec![0u8; uncompressed_length];

                let mut data = if uncompressed_length == 235 {
                    println!("{:?}", &rest[..161]);
                    vec![0u8; 235]
                } else {
                    vec![0u8; uncompressed_length]
                };
                // let mut data = vec![0u8; uncompressed_length];
                // // TODO here we fail at some point
                // ZlibDecoder::new(rest).read_to_end(&mut data)?
                match z.read_exact(&mut data) {
                    Ok(()) => {}
                    Err(e) => {
                        let compressed_size = z.total_in() as usize;
                        println!("{:?}", e);
                        println!("trying to read {uncompressed_length} bytes, {restl} remaining");
                        println!("read {} bytes", data.len());
                        println!("{:?}", data);
                        println!("{compressed_size}");
                        panic!("");
                    }
                }

                // let mut data = Vec::new();
                // let mut chunk = vec![0u8, 1];
                // println!("{}", chunk.len());
                // let mut total_read = 0;
                // while total_read < uncompressed_length {
                //     match z.read(&mut chunk) {
                //         Ok(0) => break, // EOF reached
                //         Ok(n) => {
                //             data.push(chunk[0]);
                //             total_read += n;
                //             // println!("{n} read, {uncompressed_length} expected");
                //         }
                //         Err(e) => {
                //             println!("{:?}", e);
                //             panic!("");
                //         }
                //     }
                // }
                //
                // if total_read != uncompressed_length {
                //     panic!("");
                // }

                let compressed_size = z.total_in() as usize;

                // TODO serialize commit using object
                // TODO do we need to uncompress to hash?
                // sha = hashed content
                // TODO all the unwraps
                let buf = Vec::new();
                let mut writer = GitObjectWriter::new(buf);
                writer
                    .write_all(format!("commit {}\0", data.len()).as_bytes())
                    .unwrap();
                writer.write_all(&data).unwrap();
                let (compressed, hash) = writer.finish().unwrap();

                let commit = Object::new_commit(uncompressed_length, hash, &compressed);
                commit.write().unwrap();

                println!(
                    "{} commit {uncompressed_length} {} {offset}",
                    hex::encode(hash),
                    compressed_size + 2,
                );
                &rest[compressed_size..]
            }
            PackObjectType::Tree => {
                let mut z = ZlibDecoder::new(rest);
                let mut data = vec![0u8; uncompressed_length];
                match z.read_exact(&mut data) {
                    Ok(()) => {}
                    Err(e) => {
                        let compressed_size = z.total_in() as usize;
                        println!("{:?}", e);
                        println!("trying to read {uncompressed_length} bytes");
                        println!("read {} bytes", data.len());
                        println!("{:?}", data);
                        println!("{compressed_size}");
                        panic!("");
                    }
                }

                let compressed_size = z.total_in() as usize;

                // TODO left over data?
                let l = data.len() - 20;
                println!("{:?}", &data[l..]);
                // println!(
                //     "{:?}",
                //     std::str::from_utf8(&data[data.len() - 20..]).unwrap()
                // );

                let buf = Vec::new();
                let mut writer = GitObjectWriter::new(buf);
                writer
                    .write_all(format!("tree {}\0", l).as_bytes())
                    .unwrap();
                writer.write_all(&data[..l]).unwrap();
                let (compressed, hash) = writer.finish().unwrap();

                let commit = Object::new_tree(l, hash, &compressed);
                commit.write().unwrap();

                println!(
                    "{} tree {uncompressed_length} {} {offset}",
                    hex::encode(hash),
                    compressed_size + 2,
                );
                panic!("901908171cb8095fb2acbe6a77770005f4c155ce");
                &rest[compressed_size..]
            }
            PackObjectType::Blob => {
                panic!("not implemented");
            }
            PackObjectType::OffsetDelta => {
                panic!("not implemented");
            }
            PackObjectType::ReferenceDelta => {
                let base_sha = &rest[..20];

                let base_object = match Object::from_hash(hex::encode(base_sha).as_str()) {
                    Ok(obj) => obj,
                    Err(_e) => {
                        panic!("cant crate object from hash");
                    }
                };
                let compressed = base_object.compressed;
                let mut z = ZlibDecoder::new(&compressed[..]);
                let mut object_data = Vec::new();
                z.read_to_end(&mut object_data).unwrap();

                // advance rest pointer
                rest = &rest[20..];

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
                        let new_data = &r[..len];
                        rest_decompressed = &r[len..];

                        // TODO!
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
}

fn validate_header(input: &str) -> IResult<&str, &str> {
    // Clients MUST validate the first five bytes of the response entity matches the
    // regex ^[0-9a-f]{4}#. If this test fails, clients MUST NOT continue.

    let (rest, parsed) = take(5u8)(input)?;
    // TODO use regex
    assert!(parsed == "001e#");

    let (rest, parsed) = delimited(char(' '), is_not("\n"), char('\n')).parse(rest)?;
    // TODO err and get service name? maybe we can write a generic parser for the header?
    // assert!(parsed == "service=$git-upload-pack");

    Ok((rest, parsed))
}

fn parse_head(input: &str) -> IResult<&str, (&str, HashSet<String>)> {
    // TODO why is that not 0000\n?
    // 0000 0159 9b36649874280c532f7c06f16b7d7c9aa86073c3 HEADmulti_ack thin-pack side-band side-band-6
    // 4k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack
    // _detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want no-done symref=HEAD:refs/heads/m
    // ain filter object-format=sha1 agent=git/github-5a2d4c40a633-Linux

    // dirty, cleanup and check things (eg len)
    let (rest, _zeros) = take(4u8)(input)?;
    let (rest, _len) = take(4u8)(rest)?;
    let (rest, sha) = take(40u8)(rest)?;

    // TODO store capabilities?
    let (rest, _head) = take_until("\0")(rest)?;
    let (rest, capabilities) = take_until("\n")(rest)?;
    let (rest, _) = char('\n')(rest)?;

    let capabilities = capabilities
        .to_owned()
        .split_whitespace()
        .map(String::from)
        .collect();

    Ok((rest, (sha, capabilities)))
}

fn parse_ref_list(input: &str) -> IResult<&str, RefSpec> {
    // 003d9b36649874280c532f7c06f16b7d7c9aa86073c3 refs/heads/main
    // 003e3fcffffcacaf807d6eaf97ce5ac8131fab2a39db refs/pull/1/head
    // 003e48fc09b90b2db56dd7a36e70fc98991086ace882 refs/pull/2/head

    // let (_rest, (refs, _)) = many_till(parse_ref_list, tag("\n"))
    //     .parse(rest)
    //     .map_err(|e| anyhow::anyhow!("Failed to parse ref list: {:?}", e))?;

    let (rest, _len) = take(4u8)(input)?;
    let (rest, sha) = take(40u8)(rest)?;
    let (rest, _) = char(' ')(rest)?;
    let (rest, ref_name) = take_until("\n")(rest)?;
    let (rest, _) = char('\n')(rest)?;

    // let len = usize::from_str_radix(len, 16);
    // println!("{:?} == {:?}", len, sha.len() + ref_name.len() + 2);
    // assert!(len == Ok(sha.len() + ref_name.len() + 2));

    Ok((
        rest,
        RefSpec {
            sha: sha.to_owned(),
            name: ref_name.to_owned(),
        },
    ))
}

impl Refs {
    pub(crate) fn from_response(response: &str) -> anyhow::Result<Self> {
        let (rest, _parsed) = validate_header(response)
            .map_err(|e| anyhow::anyhow!("Failed to validate header: {:?}", e))?;

        let (rest, (sha, capabilities)) =
            parse_head(rest).map_err(|e| anyhow::anyhow!("Failed to parse head: {:?}", e))?;

        let (_, refs) = fold_many0(
            preceded(not(tag("0000")), parse_ref_list),
            Vec::new,
            |mut acc: Vec<RefSpec>, item: RefSpec| {
                acc.push(item);
                acc
            },
        )
        .parse(rest)
        .map_err(|e| anyhow::anyhow!("Failed to parse ref list: {:?}", e))?;

        Ok(Refs {
            head: sha.to_owned(),
            capabilities,
            refs,
        })
    }
}

pub(crate) fn invoke(url: &str, path: Option<String>) -> anyhow::Result<()> {
    let path = match path {
        None => {
            let v: Vec<&str> = url.split('/').collect();
            let name = v.last().unwrap().to_string();
            name.split(".")
                .collect::<Vec<&str>>()
                .first()
                .unwrap()
                .to_string()
        }
        Some(path) => path,
    };
    fs::create_dir(path.clone())?;
    env::set_current_dir(path)?;
    init::invoke()?;

    let client = reqwest::blocking::Client::new();
    let response = client
        .get(format!("{url}/info/refs?service=git-upload-pack"))
        .send()?;
    let body = response.text()?;
    let refs = Refs::from_response(body.as_str())?;

    let mut headers = header::HeaderMap::new();
    headers.insert(
        "Content-Type",
        header::HeaderValue::from_static("application/x-git-upload-pack-request"),
    );
    headers.insert(
        "Git-Protocol",
        header::HeaderValue::from_static("version=2"),
    );

    // https://git-scm.com/docs/protocol-v2
    // TODO: could not piece this together from the docs without peeking at a
    // real output I get when running:
    //   GIT_TRACE_CURL=1 git clone https://github.com/iff/fleet.git &> out
    // Send data: 0011command=fetch001aagent=git/2.50.1-Linux0016object-format
    // Send data: =sha10001000dthin-pack000fno-progress000dofs-delta0032want 9
    // Send data: b36649874280c532f7c06f16b7d7c9aa86073c3.0032want 9b366498742
    // Send data: 80c532f7c06f16b7d7c9aa86073c3.0009done.0000
    // Info: upload completely sent off: 223 bytes
    // NOTE not sure why we need this special preamble and why we need to request the want twice?
    let body = format!("0011command=fetch0016object-format=sha10001000fno-progress0032want {}\n0032want {}\n0009done\n0000", refs.head, refs.head);

    let response = client
        .post(format!("{url}/git-upload-pack"))
        .headers(headers)
        .body(body)
        .send()?;

    // TODO only the simplest case will we directly get the pack file (clone is probably that)
    // https://github.com/git/git/blob/795ea8776befc95ea2becd8020c7a284677b4161/Documentation/gitformat-pack.txt
    let pack = response.bytes()?;

    // trying to debug the response.. it seems to be different then what I get on disk after a new
    // clone and idx is missing to run git verify-pack
    // std::fs::write(String::from("sha.pack"), &pack[18..])?;

    let (rest, (version, num_objects)) =
        pack::parse_header(&pack).map_err(|e| anyhow::anyhow!("Failed to parse pack: {:?}", e))?;

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
        assert_eq!(2, before - new_rest.len());

        let new_rest = pack::parse_object(object_type, length, new_rest, offset);
        // println!("object parsed {} bytes", before - new_rest.len());
        offset += before - new_rest.len();
        rest = new_rest;
    }

    // NOTE last 20 bytes are the SHA1 checksum of the entire pack content
    // TODO verify using something like our object writer

    Ok(())
}
