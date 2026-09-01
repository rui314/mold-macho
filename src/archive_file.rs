//! Static archive (.a) reading, mirroring mold-rust's archive_file.rs.
//!
//! A Mach-O archive is the common ar format: a "!<arch>\n" magic, then
//! 60-byte member headers. Apple's ar uses the BSD long-name
//! convention - a member name of "#1/<len>" means the real name is the
//! first <len> bytes of the member body - and prepends a __.SYMDEF
//! index member, which a linker that parses every member eagerly can
//! simply skip.

use crate::arch::Arch;
use crate::context::Context;
use crate::fatal;
use crate::mapped_file::MappedFile;

/// Splits an archive into its members. Members use the BSD convention:
/// a name of "#1/<len>" means the real name is the first <len> bytes of
/// the member data.
pub fn read_archive_members<E: Arch>(
    ctx: &Context<E>,
    mf: &'static MappedFile,
) -> Vec<&'static MappedFile> {
    let data = mf.data;
    let mut members = Vec::new();
    let mut off = 8;

    while off + 60 <= data.len() {
        let hdr = &data[off..off + 60];
        let field = |range: std::ops::Range<usize>| {
            std::str::from_utf8(&hdr[range])
                .unwrap_or("")
                .trim_end()
                .to_string()
        };
        let name = field(0..16);
        let Ok(size) = field(48..58).parse::<usize>() else {
            fatal!(ctx, "{}: malformed archive member header", mf.name);
        };

        let mut body = off + 60;
        let mut body_size = size;
        let name = if let Some(len) = name.strip_prefix("#1/") {
            let Ok(len) = len.parse::<usize>() else {
                fatal!(ctx, "{}: malformed archive member name", mf.name);
            };
            let raw = &data[body..body + len];
            body += len;
            body_size -= len;
            let end = raw.iter().position(|&b| b == 0).unwrap_or(len);
            String::from_utf8_lossy(&raw[..end]).into_owned()
        } else {
            name
        };

        if !name.starts_with("__.SYMDEF") {
            let full_name = format!("{}({})", mf.name, name);
            members.push(mf.slice(full_name, &data[body..body + body_size]));
        }

        off += 60 + size;
        off += off & 1; // members are aligned to even offsets
    }
    members
}
