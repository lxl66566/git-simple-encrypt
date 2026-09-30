//! Server side of git's long-running process filter protocol
//! (`filter.<driver>.process`).
//!
//! One daemon serves every blob of a single git invocation, replacing the
//! per-file clean/smudge process spawns (the 50-100ms process cold start +
//! repo open + Argon2 per file). Wire format is pkt-line (see
//! [`super::pktline`]); after the version/capability handshake, git sends one
//! `key=value` command list (flush-terminated) plus the content as data
//! packets (flush-terminated). The response is a status list, the filtered
//! content, and a second status list — which may turn an already-streamed
//! `status=success` into `status=error`.
//!
//! Failure mapping:
//! - per-blob failures (unsupported future version, corrupt ciphertext, ...) answer `status=error`
//!   and keep serving;
//! - failures that repeat identically for every future command (no usable password, broken Argon2)
//!   answer `status=abort` — git then refuses the whole operation — and the session ends.
//!
//! `delay` is deliberately NOT declared: it exists to let filters postpone
//! work past checkout, which the synchronous crypto here does not need (a
//! capability the server does not echo is one git will never use). There is
//! no `no-flush` capability in the protocol — the flush packets around the
//! content are mandatory framing, not an option. Stdout carries protocol
//! bytes only; all logging goes to stderr.

use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    path::PathBuf,
};

use log::error;

use super::{FilterContext, SaltSource, clean_stream, decrypt_stream, pktline};
use crate::{
    crypt::cache_key,
    error::{Error, Result},
    repo::Repo,
};

/// What the session does after one handled request.
enum Flow {
    /// Keep serving (success or per-file error).
    Continue,
    /// An abort was sent: the session is over for this git process.
    Stop,
}

/// A command from git's command list.
#[derive(Clone, Copy)]
enum Command {
    Clean,
    Smudge,
}

impl Command {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "clean" => Some(Self::Clean),
            "smudge" => Some(Self::Smudge),
            _ => None,
        }
    }
}

/// One parsed request.
enum Request {
    /// A known command with its pathname.
    Command { command: Command, pathname: PathBuf },
    /// A parseable command list we cannot act on (unknown/missing command or
    /// missing pathname). Its content section still needs consuming to keep
    /// the stream aligned.
    Unsupported,
}

/// Failures that repeat identically for every future command of this git
/// process.
///
/// The password is checked up front and aborts on its own; Argon2 breakage
/// (e.g. a misconfigured build) breaks every derivation to come.
const fn session_fatal(e: &Error) -> bool {
    matches!(e, Error::Argon2(_))
}

/// Entry point of the `git-se filter-process` subcommand: serve the process
/// filter protocol on stdin/stdout until git closes the pipe.
pub fn serve(repo: &Repo) -> Result<()> {
    serve_io(repo, io::stdin().lock(), io::stdout().lock())
}

/// Protocol engine over arbitrary streams, so tests can drive a full session
/// in-process.
pub fn serve_io<R: Read, W: Write>(repo: &Repo, input: R, output: W) -> Result<()> {
    // 4-byte prefix reads must not hit the raw pipe per packet.
    let mut input = BufReader::with_capacity(64 * 1024, input);
    // Room for one maximum packet, so a whole packet is one syscall; flushed
    // after every complete response (git synchronously waits for it).
    let mut output = BufWriter::with_capacity(pktline::MAX_PAYLOAD + 64, output);

    handshake(&mut input, &mut output)?;
    let ctx = FilterContext::new(repo, SaltSource::Process);
    command_loop(&ctx, &mut input, &mut output)
}

/// Version and capability negotiation (the only version is 2; the reply must
/// be a subset of git's offered capabilities, which clean+smudge always is).
fn handshake<R: Read, W: Write>(input: &mut BufReader<R>, output: &mut BufWriter<W>) -> Result<()> {
    expect_line(input, "git-filter-client")?;

    let mut version2 = false;
    loop {
        match pktline::read_pkt(input)? {
            pktline::Pkt::Flush => break,
            pktline::Pkt::Data(line) => version2 |= chomp(&line) == b"version=2",
        }
    }
    if !version2 {
        return Err(Error::Other(
            "git filter process protocol: version 2 was not offered".into(),
        ));
    }
    pktline::write_line(output, "git-filter-server")?;
    pktline::write_line(output, "version=2")?;
    pktline::write_flush(output)?;
    output.flush()?;

    // Git's capability list (clean/smudge/delay, plus whatever the future
    // adds) only needs consuming; the fixed reply below is always a subset.
    loop {
        match pktline::read_pkt(input)? {
            pktline::Pkt::Flush => break,
            pktline::Pkt::Data(_) => {},
        }
    }
    pktline::write_line(output, "capability=clean")?;
    pktline::write_line(output, "capability=smudge")?;
    pktline::write_flush(output)?;
    output.flush()?;
    Ok(())
}

/// Expect exactly one LF-terminated text packet.
fn expect_line(input: &mut impl Read, line: &str) -> Result<()> {
    match pktline::read_pkt(input)? {
        pktline::Pkt::Data(data) if chomp(&data) == line.as_bytes() => Ok(()),
        data => Err(Error::Other(format!(
            "git filter process protocol: expected {line:?}, got {data:?}"
        ))),
    }
}

/// Drop one trailing LF (git chomps one on read; its writers always add one).
fn chomp(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n").unwrap_or(line)
}

/// Read the next request. `Ok(None)` is a clean pipe close (git is done).
fn read_request<R: Read>(input: &mut BufReader<R>) -> Result<Option<Request>> {
    let mut command: Option<Command> = None;
    let mut pathname: Option<PathBuf> = None;
    loop {
        let pkt = match pktline::read_pkt(input) {
            Ok(pkt) => pkt,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let pktline::Pkt::Data(line) = pkt else { break };
        let line = String::from_utf8_lossy(&line);
        let line = line.strip_suffix('\n').unwrap_or(&line);
        // The key never contains '='; the value may.
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::Other(
                "git filter process protocol: malformed command list".into(),
            ));
        };
        match key {
            "command" => command = Command::parse(value),
            "pathname" => pathname = Some(PathBuf::from(value)),
            // ref=/treeish=/blob= and future keys carry no behavior here.
            _ => {},
        }
    }
    Ok(Some(match (command, pathname) {
        (Some(command), Some(pathname)) => Request::Command { command, pathname },
        _ => Request::Unsupported,
    }))
}

fn command_loop<R: Read, W: Write>(
    ctx: &FilterContext<'_>,
    input: &mut BufReader<R>,
    output: &mut BufWriter<W>,
) -> Result<()> {
    loop {
        // None = git closed the pipe: normal end of the session.
        let Some(request) = read_request(input)? else {
            return Ok(());
        };
        match handle_request(ctx, input, output, request)? {
            Flow::Continue => {},
            Flow::Stop => return Ok(()),
        }
    }
}

fn handle_request<R: Read, W: Write>(
    ctx: &FilterContext<'_>,
    input: &mut BufReader<R>,
    output: &mut BufWriter<W>,
    request: Request,
) -> Result<Flow> {
    let mut content = pktline::PktReader::new(input);

    let Request::Command { command, pathname } = request else {
        content.finish()?;
        error!("git-se filter-process: command list without a usable command/pathname");
        pktline::write_line(output, "status=error")?;
        pktline::write_flush(output)?;
        output.flush()?;
        return Ok(Flow::Continue);
    };

    // The password gates every command: fetch it before the response starts,
    // so an unusable key ends the session with one abort instead of failing
    // file by file.
    if let Err(e) = ctx.password() {
        content.finish()?;
        error!("git-se filter-process: {e}");
        pktline::write_line(output, "status=abort")?;
        pktline::write_flush(output)?;
        output.flush()?;
        return Ok(Flow::Stop);
    }

    // Status first, then the streamed content section.
    pktline::write_line(output, "status=success")?;
    pktline::write_flush(output)?;
    let mut payload = pktline::PktWriter::new(output);
    let result = match command {
        Command::Clean => clean_stream(ctx, &pathname, &mut content, &mut payload),
        Command::Smudge => {
            let key = cache_key(&pathname, ctx.repo.path());
            decrypt_stream(ctx, &mut content, &mut payload, Some(&key))
        },
    };
    // The cores read to EOF on success, but an error can leave unread
    // payload behind — always drain to the flush so the next command parses.
    content.finish()?;
    // Close the content section even on failure; the second status list may
    // then override the streamed success.
    payload.finish()?;

    match result {
        Ok(()) => pktline::write_flush(output)?, // empty list: keep success
        Err(e) if session_fatal(&e) => {
            error!("git-se filter-process: {} ({})", e, pathname.display());
            pktline::write_line(output, "status=abort")?;
            pktline::write_flush(output)?;
            output.flush()?;
            return Ok(Flow::Stop);
        },
        Err(e) => {
            error!("git-se filter-process: {} ({})", e, pathname.display());
            pktline::write_line(output, "status=error")?;
            pktline::write_flush(output)?;
        },
    }
    output.flush()?;
    Ok(Flow::Continue)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, io::Cursor, process::Command};

    use path_absolutize::Absolutize;
    use tempfile::TempDir;

    use super::*;
    use crate::{crypt::HEADER_LEN, filter::is_ciphertext, salt_cache::SaltCacheReader};

    const FLUSH: &[u8] = b"0000";

    fn init_repo() -> (TempDir, Repo) {
        let dir = TempDir::new().unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        let repo_path = dir.path().absolutize().unwrap().to_path_buf();
        let repo = Repo::open(&repo_path).unwrap();
        repo.set_config("key", "test-key").unwrap();
        (dir, repo)
    }

    // ---- protocol scripting helpers (the "git" side) ----

    /// One LF-terminated text packet.
    fn line(line: &str) -> Vec<u8> {
        let payload = format!("{line}\n");
        let mut v = format!("{:04x}", payload.len() + 4).into_bytes();
        v.extend_from_slice(payload.as_bytes());
        v
    }

    /// One binary data packet.
    fn data(bytes: &[u8]) -> Vec<u8> {
        let mut v = format!("{:04x}", bytes.len() + 4).into_bytes();
        v.extend_from_slice(bytes);
        v
    }

    fn concat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    fn handshake_request() -> Vec<u8> {
        concat(&[
            &line("git-filter-client"),
            &line("version=2"),
            FLUSH,
            &line("capability=clean"),
            &line("capability=smudge"),
            &line("capability=delay"),
            FLUSH,
        ])
    }

    fn expected_handshake_response() -> Vec<u8> {
        concat(&[
            &line("git-filter-server"),
            &line("version=2"),
            FLUSH,
            &line("capability=clean"),
            &line("capability=smudge"),
            FLUSH,
        ])
    }

    /// A command request, with its content packetized the way git sends it:
    /// chunks at the maximum payload size, then a flush packet.
    fn command(command: &str, pathname: &str, content: &[u8]) -> Vec<u8> {
        let mut v = concat(&[
            &line(&format!("command={command}")),
            &line(&format!("pathname={pathname}")),
            &line("ref=refs/heads/main"), // informational key: must be ignored
            FLUSH,
        ]);
        for chunk in content.chunks(pktline::MAX_PAYLOAD) {
            v.extend_from_slice(&data(chunk));
        }
        v.extend_from_slice(FLUSH);
        v
    }

    // ---- response parsing ----

    fn read_pkt(cur: &mut Cursor<Vec<u8>>) -> pktline::Pkt {
        pktline::read_pkt(cur).unwrap()
    }

    /// One key=value list terminated by flush.
    fn read_list(cur: &mut Cursor<Vec<u8>>) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            match read_pkt(cur) {
                pktline::Pkt::Flush => return out,
                pktline::Pkt::Data(bytes) => {
                    out.push(String::from_utf8_lossy(&bytes).trim_end().to_owned());
                },
            }
        }
    }

    fn read_content(cur: &mut Cursor<Vec<u8>>) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            match read_pkt(cur) {
                pktline::Pkt::Flush => return out,
                pktline::Pkt::Data(bytes) => out.extend_from_slice(&bytes),
            }
        }
    }

    /// One response: (status list, content, final status list). Only a
    /// `status=success` response carries a content section and a second
    /// status list; error/abort responses are a single list.
    type Response = (Vec<String>, Vec<u8>, Vec<String>);

    fn read_response(cur: &mut Cursor<Vec<u8>>) -> Response {
        let status = read_list(cur);
        if !status.iter().any(|s| s == "status=success") {
            return (status, Vec::new(), Vec::new());
        }
        let content = read_content(cur);
        let final_status = read_list(cur);
        (status, content, final_status)
    }

    /// Run a session over a fully prebuilt input and return the raw output.
    fn run_session(repo: &Repo, input: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        serve_io(repo, Cursor::new(input.to_vec()), &mut output)?;
        Ok(output)
    }

    /// Parse a session output into handshake bytes + the response tuples.
    fn parse_session(out: Vec<u8>) -> (Vec<u8>, Vec<Response>) {
        let handshake_len = expected_handshake_response().len();
        let mut cur = Cursor::new(out);
        cur.set_position(u64::try_from(handshake_len).unwrap());
        let mut responses = Vec::new();
        while usize::try_from(cur.position()).unwrap() < cur.get_ref().len() {
            responses.push(read_response(&mut cur));
        }
        let mut out = cur.into_inner();
        out.truncate(handshake_len);
        (out, responses)
    }

    #[test]
    fn handshake_and_clean_smudge_roundtrip() {
        let (_dir, repo) = init_repo();

        // Reference ciphertext for the smudge input, minted through the
        // one-shot driver (proves clean/smudge <-> process interop).
        let ctx = FilterContext::new(&repo, SaltSource::PerFile);
        let mut ciphertext = Vec::new();
        let mut input = Cursor::new(b"alpha".to_vec());
        clean_stream(
            &ctx,
            std::path::Path::new("a.txt"),
            &mut input,
            &mut ciphertext,
        )
        .unwrap();
        assert!(is_ciphertext(&ciphertext));

        let script = concat(&[
            &handshake_request(),
            &command("clean", "a.txt", b"alpha"),
            &command("smudge", "a.txt", &ciphertext),
            &command("clean", "a.txt", b"alpha"), // determinism within the session
        ]);
        let out = run_session(&repo, &script).unwrap();
        let (handshake, responses) = parse_session(out);

        assert_eq!(handshake, expected_handshake_response());
        assert_eq!(responses.len(), 3);

        // clean: success + encrypted content, empty final list
        assert_eq!(responses[0].0, ["status=success"]);
        assert!(is_ciphertext(&responses[0].1));
        assert!(responses[0].1.len() > HEADER_LEN);
        assert_eq!(responses[0].2, Vec::<String>::new());

        // smudge: the exact plaintext comes back; the cache entry is recorded
        assert_eq!(
            responses[1],
            (vec!["status=success".into()], b"alpha".to_vec(), Vec::new())
        );
        assert!(SaltCacheReader::load(repo.path()).get(b"a.txt").is_some());

        // the second clean reproduces the first ciphertext byte for byte
        assert_eq!(responses[2].1, responses[0].1);
    }

    #[test]
    fn process_mode_shares_one_salt_across_misses() {
        let (_dir, repo) = init_repo();
        let script = concat(&[
            &handshake_request(),
            &command("clean", "x.txt", b"x"),
            &command("clean", "y.txt", b"y"),
            &command("clean", "sub/z.txt", b"z"),
        ]);
        let out = run_session(&repo, &script).unwrap();
        let (_, responses) = parse_session(out);
        assert!(
            responses
                .iter()
                .all(|(s, _, f)| s.as_slice() == ["status=success"] && f.is_empty())
        );

        let reader = SaltCacheReader::load(repo.path());
        let salts: HashSet<_> = ["x.txt", "y.txt", "sub/z.txt"]
            .into_iter()
            .map(|p| reader.get(p.as_bytes()).unwrap().salt)
            .collect();
        assert_eq!(salts.len(), 1, "one session shares one batch salt");

        // A separate session mints a fresh batch salt.
        let script = concat(&[&handshake_request(), &command("clean", "w.txt", b"w")]);
        run_session(&repo, &script).unwrap();
        let reader = SaltCacheReader::load(repo.path());
        assert!(!salts.contains(&reader.get(b"w.txt").unwrap().salt));
    }

    /// Per-file failures answer status=error and the session keeps serving.
    #[test]
    fn per_file_error_keeps_session_alive() {
        let (_dir, repo) = init_repo();

        // A future-version GITSE payload: smudge must refuse it...
        let mut future = vec![0u8; HEADER_LEN + 4];
        future[..5].copy_from_slice(b"GITSE");
        future[5] = 4;
        future[7] = 1;
        future[HEADER_LEN..].copy_from_slice(b"tail");
        // ...and clean must pass it through byte-identically.
        let clean_script = command("clean", "fut.txt", &future);

        let script = concat(&[
            &handshake_request(),
            &command("smudge", "fut.txt", &future),
            &command("smudge", "fut.txt", b"not encrypted"), // passthrough
            &clean_script,
            &command("teleport", "x.txt", b"data"), // unknown command
            &command("clean", "ok.txt", b"still alive"),
        ]);
        let out = run_session(&repo, &script).unwrap();
        let (_, responses) = parse_session(out);
        assert_eq!(responses.len(), 5);

        // smudge of a future-version file: streamed success turns into error
        assert_eq!(
            responses[0],
            (vec!["status=success".into()], Vec::new(), vec![
                "status=error".into()
            ])
        );
        // plaintext smudges through unchanged
        assert_eq!(
            responses[1],
            (
                vec!["status=success".into()],
                b"not encrypted".to_vec(),
                Vec::new()
            )
        );
        // clean passes the future-version file through byte-identically
        assert_eq!(
            responses[2],
            (vec!["status=success".into()], future, Vec::new())
        );
        // unknown command: bare error (no content section)
        assert_eq!(
            responses[3],
            (vec!["status=error".into()], Vec::new(), Vec::new())
        );
        // the session still serves the next command
        assert_eq!(responses[4].0, ["status=success"]);
        assert!(is_ciphertext(&responses[4].1));
    }

    /// A wrong password fails per file (AEAD error), not the whole session.
    #[test]
    fn wrong_password_reports_per_file_error() {
        let (_dir, repo) = init_repo();
        let ctx = FilterContext::new(&repo, SaltSource::PerFile);
        let mut ciphertext = Vec::new();
        let mut input = Cursor::new(b"secret".to_vec());
        clean_stream(
            &ctx,
            std::path::Path::new("a.txt"),
            &mut input,
            &mut ciphertext,
        )
        .unwrap();

        repo.set_config("key", "a-different-key").unwrap();

        let script = concat(&[
            &handshake_request(),
            &command("smudge", "a.txt", &ciphertext),
            &command("clean", "b.txt", b"other"), // clean uses the new key fine
        ]);
        let out = run_session(&repo, &script).unwrap();
        let (_, responses) = parse_session(out);
        assert_eq!(
            responses[0].2,
            ["status=error"],
            "wrong password must surface as a per-file error"
        );
        assert_eq!(responses[1].0, ["status=success"]);
    }

    /// No usable password: one status=abort, then the process exits (an
    /// error per file would just repeat the identical failure).
    #[test]
    fn missing_key_aborts_the_session() {
        let dir = TempDir::new().unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        let repo_path = dir.path().absolutize().unwrap().to_path_buf();
        let repo = Repo::open(&repo_path).unwrap(); // key deliberately unset

        let script = concat(&[
            &handshake_request(),
            &command("clean", "a.txt", b"plain"),
            &command("clean", "b.txt", b"more"), // must never be answered
        ]);
        let out = run_session(&repo, &script).unwrap();
        let (handshake, responses) = parse_session(out);
        assert_eq!(handshake, expected_handshake_response());
        assert_eq!(
            responses,
            [(vec!["status=abort".to_string()], Vec::new(), Vec::new())],
            "exactly one abort response, no content section"
        );
    }

    /// EOF right after the handshake is the normal end of a git operation.
    #[test]
    fn eof_after_handshake_exits_cleanly() {
        let (_dir, repo) = init_repo();
        let out = run_session(&repo, &handshake_request()).unwrap();
        assert_eq!(out, expected_handshake_response());
    }

    /// Handshake violations end the process with an error instead of a
    /// garbage conversation.
    #[test]
    fn bad_handshake_is_rejected() {
        let (_dir, repo) = init_repo();

        let wrong_welcome = concat(&[&line("git-filter-server"), &line("version=2"), FLUSH]);
        assert!(run_session(&repo, &wrong_welcome).is_err());

        let wrong_version = concat(&[&line("git-filter-client"), &line("version=3"), FLUSH]);
        assert!(run_session(&repo, &wrong_version).is_err());
    }

    /// Content spanning many packets flows through both directions
    /// losslessly (chunking at the 65516-byte packet cap). The payload is
    /// incompressible so the ciphertext itself spans multiple packets.
    #[test]
    fn multi_chunk_content_roundtrip() {
        use rand::prelude::*;

        let (_dir, repo) = init_repo();
        let mut rng = SmallRng::from_seed([0x5e; 32]);
        let payload: Vec<u8> = (0..150_000).map(|_| rng.random::<u8>()).collect();

        let script = concat(&[&handshake_request(), &command("clean", "big.bin", &payload)]);
        let out = run_session(&repo, &script).unwrap();
        let (_, responses) = parse_session(out);
        assert_eq!(responses.len(), 1);
        let ciphertext = responses[0].1.clone();
        assert!(ciphertext.len() > pktline::MAX_PAYLOAD);

        // A fresh session smudges the big ciphertext back to the payload.
        let script = concat(&[
            &handshake_request(),
            &command("smudge", "big.bin", &ciphertext),
        ]);
        let out = run_session(&repo, &script).unwrap();
        let (_, responses) = parse_session(out);
        assert_eq!(responses[0].1, payload);
    }
}
