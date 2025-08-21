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

use nom::{
    bytes::complete::{is_not, take, take_until},
    character::complete::char,
    sequence::delimited,
    IResult, Parser,
};

struct RefSpec {
    sha: String, // [u8; 40],
    name: String,
}

struct Refs {
    // TODO cap_list
    head: String, //[u8; 40],
    refs: Vec<RefSpec>,
}

// 000001599b36649874280c532f7c06f16b7d7c9aa86073c3 HEADmulti_ack thin-pack side-band side-band-6
// 4k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack
// _detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want no-done symref=HEAD:refs/heads/m
// ain filter object-format=sha1 agent=git/github-5a2d4c40a633-Linux
// 003d9b36649874280c532f7c06f16b7d7c9aa86073c3 refs/heads/main
// 003e3fcffffcacaf807d6eaf97ce5ac8131fab2a39db refs/pull/1/head
// 003e48fc09b90b2db56dd7a36e70fc98991086ace882 refs/pull/2/head
// 0000

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

fn parse_head(input: &str) -> IResult<&str, (&str, &str)> {
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
    let (rest, parsed) = take_until("\n")(rest)?;
    let (rest, _) = char('\n')(rest)?;

    Ok((rest, (sha, parsed)))
}

impl Refs {
    pub(crate) fn from_response(response: &str) -> anyhow::Result<Self> {
        let (rest, _parsed) = validate_header(response)
            .map_err(|e| anyhow::anyhow!("Failed to validate header: {:?}", e))?;

        let (_rest, (sha, _cap)) =
            parse_head(rest).map_err(|e| anyhow::anyhow!("Failed to validate header: {:?}", e))?;

        // then all refs
        //   first 4 bytes are len then SHA den ref name

        // end with 0000

        Ok(Refs {
            head: sha.to_owned(),
            refs: Vec::new(),
        })
    }
}

pub(crate) fn invoke(url: &str, path: Option<String>) -> anyhow::Result<()> {
    let response = reqwest::blocking::get(format!("{url}/info/refs?service=git-upload-pack"))?;
    let body = response.text()?;
    let refs = Refs::from_response(body.as_str())?;
    println!("HEAD = {:?}", refs.head);

    Ok(())
}
