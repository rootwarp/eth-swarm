//! The `text/event-stream` format (WHATWG HTML, "Server-sent events", event stream
//! interpretation): lines end in CRLF, LF or CR; `event:` names the event, `data:` lines are
//! joined with `\n`, a line starting with `:` is a comment (beacon nodes send them as
//! keep-alives), `id:`, `retry:` and unknown fields are ignored, and a blank line dispatches the
//! event if it has data.

/// The largest line or event the parser holds: 1 MiB. Beacon API events are a few hundred
/// bytes; anything this large is not one, and the stream is dropped.
pub const MAX_EVENT_BYTES: usize = 1 << 20;
/// The longest event name: 64 bytes. Beacon API event names are under 32
/// (`execution_payload_gossip`); a longer one is not one, and the stream is dropped.
pub const MAX_EVENT_NAME_BYTES: usize = 64;

/// One dispatched event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The `event:` name (`message` when none was given).
    pub event: String,
    /// The `data:` lines joined with `\n`.
    pub data: String,
}

/// A line or event over [`MAX_EVENT_BYTES`], or an event name over [`MAX_EVENT_NAME_BYTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TooLarge {
    /// A line.
    #[error("an SSE line is over {MAX_EVENT_BYTES} bytes")]
    Line,
    /// An event's data.
    #[error("an SSE event is over {MAX_EVENT_BYTES} bytes")]
    Event,
    /// An event's name.
    #[error("an SSE event name is over {MAX_EVENT_NAME_BYTES} bytes")]
    Name,
}

/// An incremental parser: feed it the body's chunks as they arrive.
#[derive(Debug, Default)]
pub struct SseParser {
    line: Vec<u8>,
    after_cr: bool,
    event: String,
    data: String,
}

impl SseParser {
    /// Parses `chunk`, returning every event it completes.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, TooLarge> {
        let mut events = Vec::new();
        for &b in chunk {
            let after_cr = std::mem::replace(&mut self.after_cr, b == b'\r');
            match b {
                // The LF of a CRLF whose CR ended the previous line.
                b'\n' if after_cr => {}
                b'\n' | b'\r' => {
                    let line = std::mem::take(&mut self.line);
                    if let Some(event) = self.line_done(&line)? {
                        events.push(event);
                    }
                }
                _ => {
                    if self.line.len() >= MAX_EVENT_BYTES {
                        return Err(TooLarge::Line);
                    }
                    self.line.push(b);
                }
            }
        }
        Ok(events)
    }

    fn line_done(&mut self, line: &[u8]) -> Result<Option<SseEvent>, TooLarge> {
        if line.is_empty() {
            let event = std::mem::take(&mut self.event);
            if self.data.is_empty() {
                return Ok(None);
            }
            let mut data = std::mem::take(&mut self.data);
            data.pop(); // the last `\n`
            let event = if event.is_empty() {
                "message".to_owned()
            } else {
                event
            };
            return Ok(Some(SseEvent { event, data }));
        }
        if line[0] == b':' {
            return Ok(None);
        }
        let line = String::from_utf8_lossy(line);
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (&*line, ""),
        };
        match field {
            "event" => {
                if value.len() > MAX_EVENT_NAME_BYTES {
                    return Err(TooLarge::Name);
                }
                self.event = value.to_owned();
            }
            "data" => {
                if self.data.len() + value.len() >= MAX_EVENT_BYTES {
                    return Err(TooLarge::Event);
                }
                self.data.push_str(value);
                self.data.push('\n');
            }
            _ => {}
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(event: &str, data: &str) -> SseEvent {
        SseEvent {
            event: event.into(),
            data: data.into(),
        }
    }

    #[test]
    fn events_comments_and_fields() {
        let mut p = SseParser::default();
        let text = ": keep-alive\n\nevent: block_gossip\ndata: {\"slot\":\"1\"}\n\n\
                    data:a\ndata: b\nid: 7\nretry: 100\nfoo\n\nevent: x\n\n";
        let got = p.feed(text.as_bytes()).unwrap();
        // An event without data is not dispatched.
        assert_eq!(
            got,
            vec![
                ev("block_gossip", "{\"slot\":\"1\"}"),
                ev("message", "a\nb")
            ]
        );
        // The name of an undispatched event does not leak into the next one.
        assert_eq!(p.feed(b"data: z\n\n").unwrap(), vec![ev("message", "z")]);
    }

    #[test]
    fn every_line_ending_and_split_chunks() {
        let text = b"event: a\r\ndata: 1\r\n\r\nevent: b\rdata: 2\r\revent: c\ndata: 3\n\n";
        let want = vec![ev("a", "1"), ev("b", "2"), ev("c", "3")];
        let mut whole = SseParser::default();
        assert_eq!(whole.feed(text).unwrap(), want);
        // One byte at a time: a CR at the end of a chunk and its LF in the next are one line end.
        let mut bytewise = SseParser::default();
        let mut got = Vec::new();
        for b in text {
            got.extend(bytewise.feed(&[*b]).unwrap());
        }
        assert_eq!(got, want);
    }

    #[test]
    fn an_unfinished_event_waits() {
        let mut p = SseParser::default();
        assert_eq!(p.feed(b"event: a\ndata: 1\n").unwrap(), vec![]);
        assert_eq!(p.feed(b"\n").unwrap(), vec![ev("a", "1")]);
    }

    #[test]
    fn oversized_lines_and_events_are_refused() {
        let mut p = SseParser::default();
        let long = vec![b'x'; MAX_EVENT_BYTES + 1];
        assert_eq!(p.feed(&long), Err(TooLarge::Line));

        let mut p = SseParser::default();
        let line = format!("data: {}\n", "y".repeat(MAX_EVENT_BYTES / 2));
        assert_eq!(p.feed(line.as_bytes()).unwrap(), vec![]);
        assert_eq!(p.feed(line.as_bytes()), Err(TooLarge::Event));
    }

    #[test]
    fn an_oversized_event_name_is_refused() {
        let mut p = SseParser::default();
        let name = "n".repeat(MAX_EVENT_NAME_BYTES);
        let fits = format!("event: {name}\ndata: 1\n\n");
        assert_eq!(p.feed(fits.as_bytes()).unwrap(), vec![ev(&name, "1")]);
        let over = format!("event: {name}x\ndata: 1\n\n");
        let err = p.feed(over.as_bytes()).unwrap_err();
        assert_eq!(err, TooLarge::Name);
        assert_eq!(err.to_string(), "an SSE event name is over 64 bytes");
    }

    #[test]
    fn invalid_utf8_is_replaced() {
        let mut p = SseParser::default();
        let got = p.feed(b"data: \xff\n\n").unwrap();
        assert_eq!(got, vec![ev("message", "\u{fffd}")]);
    }
}
