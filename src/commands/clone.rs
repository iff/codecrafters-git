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

use std::{collections::HashSet, env, fs};

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
use crate::pack;

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
    let (rest, _) = pack::parse_network_header(&pack)
        .map_err(|e| anyhow::anyhow!("Failed to parse pack: {:?}", e))?;

    let mut offset = rest.len();
    let data = &rest;
    let (rest, (version, num_objects)) =
        pack::parse_header(rest).map_err(|e| anyhow::anyhow!("Failed to parse pack: {:?}", e))?;
    assert!(version == 2);
    offset -= rest.len();

    let mut rest = rest;
    for _ in 0..num_objects {
        let (new_rest, (object_type, length)) = pack::parse_object_header(rest)
            .map_err(|e| anyhow::anyhow!("Failed to parse pack: {:?}", e))?;

        let new_rest = pack::parse_object(data, object_type, length, new_rest, offset);
        offset += rest.len() - new_rest.len();
        rest = new_rest;
    }

    // NOTE last 20 bytes are the SHA1 checksum of the entire pack content
    // TODO verify using something like our object writer

    Ok(())
}
