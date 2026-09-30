//! Minimal pkt-line codec for the git process filter protocol.
//!
//! Wire format: a packet is 4 hex digits — the total length including the
//! prefix — followed by `length - 4` raw payload bytes. The special prefix
//! `0000` is the flush packet; it carries no payload and terminates
//! key=value lists and content sections. Content travels as zero or more
//! data packets followed by one flush packet (there is no length-prefixed
//! raw-byte mode in this protocol). Text lines (handshake, `key=value`)
//! conventionally end with one LF; git chomps exactly one trailing LF on
//! read.

use std::io::{self, Read, Write};

use log::debug;

/// Largest payload a data packet may carry: git's `LARGE_PACKET_DATA_MAX`
/// (`LARGE_PACKET_MAX` 65520 minus the 4 prefix bytes). Git chunks streams
/// at exactly this size, and so does [`PktWriter`].
pub(super) const MAX_PAYLOAD: usize = 65516;

/// The flush packet on the wire.
const FLUSH: [u8; 4] = *b"0000";

/// Largest legal total length (prefix included) of any packet, as a `u32`
/// for direct comparison against the parsed length.
const MAX_TOTAL: u32 = 65520;
const _: () = assert!(MAX_PAYLOAD + 4 == MAX_TOTAL as usize);

/// A decoded packet.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Pkt {
    /// `0000`: terminates a key=value list or content section.
    Flush,
    /// A data packet and its raw payload bytes.
    Data(Vec<u8>),
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Decode a 4-byte length prefix into the total packet length.
///
/// Total lengths 1..=3 are reserved values of the general pkt-line format
/// (delim-pkt, response-pkt) that this protocol never uses, and anything
/// beyond git's hard packet cap cannot come from a real git.
fn decode_len(prefix: [u8; 4]) -> io::Result<usize> {
    let mut total = 0u32;
    for &b in &prefix {
        let digit = char::from(b)
            .to_digit(16)
            .ok_or_else(|| invalid("invalid pkt-line length prefix"))?;
        total = total * 16 + digit;
    }
    if !(4..=MAX_TOTAL).contains(&total) {
        return Err(invalid("pkt-line length out of range"));
    }
    usize::try_from(total).map_err(|_| invalid("pkt-line length out of range"))
}

/// Read one packet. `UnexpectedEof` means the peer closed the pipe (cleanly
/// or not); the session layer turns that into shutdown.
pub(super) fn read_pkt(reader: &mut dyn Read) -> io::Result<Pkt> {
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix)?;
    if prefix == FLUSH {
        return Ok(Pkt::Flush);
    }
    let total = decode_len(prefix)?;
    let mut payload = vec![0u8; total - 4];
    reader.read_exact(&mut payload)?;
    Ok(Pkt::Data(payload))
}

/// Write one data packet. The payload must not exceed [`MAX_PAYLOAD`];
/// longer streams go through [`PktWriter`], which chunks.
pub(super) fn write_pkt(writer: &mut dyn Write, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD {
        return Err(invalid("pkt-line payload too large"));
    }
    writer.write_all(format!("{:04x}", payload.len() + 4).as_bytes())?;
    writer.write_all(payload)
}

/// Write the flush packet.
pub(super) fn write_flush(writer: &mut dyn Write) -> io::Result<()> {
    writer.write_all(&FLUSH)
}

/// Write one LF-terminated text line as a single packet (git's framing for
/// handshake and `key=value` lines).
pub(super) fn write_line(writer: &mut dyn Write, line: &str) -> io::Result<()> {
    write_pkt(writer, format!("{line}\n").as_bytes())
}

/// Streams one content section (data packets until the flush packet) as a
/// plain [`Read`], so consumers read the payload straight off the protocol;
/// EOF at the flush packet.
pub(super) struct PktReader<'a> {
    input: &'a mut dyn Read,
    buf: Vec<u8>,
    pos: usize,
    done: bool,
}

impl<'a> PktReader<'a> {
    pub(super) fn new(input: &'a mut dyn Read) -> Self {
        Self {
            input,
            buf: Vec::new(),
            pos: 0,
            done: false,
        }
    }

    /// Consume the rest of the section up to and including the flush packet.
    /// Consumers read to EOF, so this normally only confirms the flush;
    /// skipping unread bytes keeps the stream aligned for the next command.
    pub(super) fn finish(&mut self) -> io::Result<()> {
        let mut skipped = self.buf.len() - self.pos;
        while !self.done {
            match read_pkt(self.input)? {
                Pkt::Flush => self.done = true,
                Pkt::Data(data) => skipped += data.len(),
            }
        }
        if skipped > 0 {
            debug!("git-se filter: skipped {skipped} unread content bytes");
        }
        Ok(())
    }
}

impl Read for PktReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.buf.len() {
                let n = out.len().min(self.buf.len() - self.pos);
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if self.done || out.is_empty() {
                return Ok(0);
            }
            match read_pkt(self.input)? {
                Pkt::Flush => self.done = true,
                Pkt::Data(data) => {
                    self.buf = data;
                    self.pos = 0;
                },
            }
        }
    }
}

/// Writes a content section as data packets plus the terminating flush
/// packet (on [`PktWriter::finish`]).
///
/// Payload is chunked at [`MAX_PAYLOAD`]; at most one chunk is buffered, so
/// memory stays bounded for arbitrarily large blobs.
pub(super) struct PktWriter<'a> {
    output: &'a mut dyn Write,
    buf: Vec<u8>,
}

impl<'a> PktWriter<'a> {
    pub(super) fn new(output: &'a mut dyn Write) -> Self {
        Self {
            output,
            buf: Vec::with_capacity(MAX_PAYLOAD),
        }
    }

    /// Emit the buffered bytes as one final (possibly short) packet, then
    /// the flush packet ending the content section. The protocol allows an
    /// error status after partial content, so this is also the recovery
    /// path when the crypto core failed mid-stream.
    pub(super) fn finish(mut self) -> io::Result<()> {
        self.emit()?;
        write_flush(self.output)
    }

    /// Emit the buffer as one packet (any packetization is legal) and reuse
    /// its allocation for the next chunk.
    fn emit(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        write_pkt(self.output, &self.buf)?;
        self.buf.clear();
        Ok(())
    }
}

impl Write for PktWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let len = data.len();
        let mut data = data;
        while !data.is_empty() {
            let room = MAX_PAYLOAD - self.buf.len();
            let n = room.min(data.len());
            self.buf.extend_from_slice(&data[..n]);
            data = &data[n..];
            if self.buf.len() == MAX_PAYLOAD {
                self.emit()?;
            }
        }
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// Encode `payload` as one data packet.
    fn encode(payload: &[u8]) -> Vec<u8> {
        let mut v = format!("{:04x}", payload.len() + 4).into_bytes();
        v.extend_from_slice(payload);
        v
    }

    fn read_all(reader: &mut dyn Read) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        reader.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn data_packet_roundtrip() {
        for payload in [&b""[..], b"a", b"key=value\n", &[0u8, 255, 10, 13]] {
            let mut wire = encode(payload);
            wire.extend_from_slice(&FLUSH);
            let mut cur = Cursor::new(wire);
            assert_eq!(read_pkt(&mut cur).unwrap(), Pkt::Data(payload.to_vec()));
            assert_eq!(read_pkt(&mut cur).unwrap(), Pkt::Flush);
        }
    }

    #[test]
    fn write_pkt_emits_hex_prefix() {
        // git writes lowercase hex; total length includes the 4 prefix bytes.
        let mut out = Vec::new();
        write_pkt(&mut out, b"git-filter-server\n").unwrap();
        assert_eq!(out, encode(b"git-filter-server\n"));

        let mut out = Vec::new();
        write_flush(&mut out).unwrap();
        write_line(&mut out, "status=success").unwrap();
        assert_eq!(
            out,
            [FLUSH.as_slice(), encode(b"status=success\n").as_slice()].concat()
        );
    }

    #[test]
    fn oversize_write_is_rejected() {
        let mut out = Vec::new();
        let err = write_pkt(&mut out, &vec![0u8; MAX_PAYLOAD + 1]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // exactly at the cap is fine
        write_pkt(&mut out, &vec![0u8; MAX_PAYLOAD]).unwrap();
    }

    #[test]
    fn malformed_prefixes_are_rejected() {
        for bad in [
            &b"zzzz"[..], // not hex
            b"00g0",      // not hex
            b"0001",      // delim-pkt: not part of this protocol
            b"0002",      // response-pkt
            b"0003",      // reserved
            b"ffff",      // above git's hard packet cap
        ] {
            let mut cur = Cursor::new(bad.to_vec());
            let err = read_pkt(&mut cur).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{bad:?}");
        }
    }

    #[test]
    fn truncated_packets_hit_unexpected_eof() {
        // no bytes at all: clean pipe close
        let mut cur = Cursor::new(Vec::new());
        assert_eq!(
            read_pkt(&mut cur).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        // prefix only
        let mut cur = Cursor::new(b"0009xy".to_vec());
        assert_eq!(
            read_pkt(&mut cur).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn pkt_reader_concatenates_until_flush() {
        let mut wire = encode(b"hello ");
        wire.extend_from_slice(&encode(&[0u8; 10]));
        wire.extend_from_slice(&FLUSH);
        wire.extend_from_slice(&encode(b"next section"));
        let mut cur = Cursor::new(wire);

        let mut reader = PktReader::new(&mut cur);
        let data = read_all(&mut reader).unwrap();
        assert_eq!(data, [b"hello ".to_vec(), vec![0u8; 10]].concat());
        // EOF persists; finish() finds the flush already consumed
        assert_eq!(reader.read(&mut [0u8; 8]).unwrap(), 0);
        reader.finish().unwrap();
        // the stream is aligned: the next packet parses
        assert_eq!(
            read_pkt(&mut cur).unwrap(),
            Pkt::Data(b"next section".to_vec())
        );
    }

    #[test]
    fn pkt_reader_finish_skips_unread_content() {
        let mut wire = encode(b"unread payload");
        wire.extend_from_slice(&encode(b"more"));
        wire.extend_from_slice(&FLUSH);
        let mut cur = Cursor::new(wire);
        let mut reader = PktReader::new(&mut cur);
        reader.finish().unwrap();
        // aligned at the end: EOF from here
        assert_eq!(
            read_pkt(&mut cur).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn pkt_writer_chunks_at_max_payload_and_terminates() {
        let payload: Vec<u8> = (0..MAX_PAYLOAD * 2 + 10)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let mut wire = Vec::new();
        {
            let mut writer = PktWriter::new(&mut wire);
            // write in odd-sized pieces to exercise the buffering
            for chunk in payload.chunks(9973) {
                writer.write_all(chunk).unwrap();
            }
            writer.finish().unwrap();
        }
        // parse back: two full chunks + one remainder + flush
        let mut cur = Cursor::new(wire);
        let mut decoded = Vec::new();
        loop {
            match read_pkt(&mut cur).unwrap() {
                Pkt::Flush => break,
                Pkt::Data(d) => {
                    assert!(d.len() <= MAX_PAYLOAD);
                    decoded.extend_from_slice(&d);
                },
            }
        }
        assert_eq!(decoded, payload);
        assert_eq!(
            read_pkt(&mut cur).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn pkt_writer_empty_section_is_bare_flush() {
        let mut wire = Vec::new();
        PktWriter::new(&mut wire).finish().unwrap();
        assert_eq!(wire, FLUSH.to_vec());
    }

    /// Binary losslessness through the reader/writer pair, including bytes
    /// that look like protocol framing.
    #[test]
    fn pkt_roundtrip_binary_with_framing_lookalikes() {
        let mut evil = Vec::new();
        evil.extend_from_slice(b"0000");
        evil.extend_from_slice(b"0004");
        evil.extend_from_slice(&FLUSH);
        evil.extend_from_slice(&vec![0x0a; 70000]);

        let mut wire = Vec::new();
        {
            let mut writer = PktWriter::new(&mut wire);
            writer.write_all(&evil).unwrap();
            writer.finish().unwrap();
        }
        let mut cur = Cursor::new(wire);
        let mut reader = PktReader::new(&mut cur);
        assert_eq!(read_all(&mut reader).unwrap(), evil);
    }
}
