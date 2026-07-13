# Architecture

`seehandshake` is a single crate that exposes both a library (`lib.rs`) and a
binary (`main.rs`). Splitting library from binary keeps all business logic
testable and leaves the CLI as a thin translation layer over the library API.

## Module layout

```
src/
├── lib.rs             crate-level docs, public re-exports
├── main.rs            thin: parse args, dispatch to cli::run
├── cli.rs             clap definitions, subcommand handlers
├── error.rs           thiserror::Error enum for the library
├── model/             shared, dependency-free data types
├── parser/            TLS record + handshake decoders
├── tracker/           per-connection state, reassembly, eviction
├── capture/           PacketSource trait + libpcap-backed live source
├── ui/                Ratatui three-panel interface
└── util/              small shared helpers
```

## Threading model

Three logical stages, connected by `std::sync::mpsc` channels. No async
runtime, no global mutable state.

```
┌──────────────┐  Frame   ┌────────────────────┐  UiEvent   ┌──────────┐
│  capture     │─────────▶│  parser + tracker  │───────────▶│    UI    │
│  thread      │          │  thread            │            │  (main)  │
└──────────────┘          └────────────────────┘            └──────────┘
        ▲                                                        │
        │                                                     crossterm
   pcap::Capture                                              (keyboard)
```

Each thread owns its data. The only shared surface is the channels between
them, which carry owned values.

### Capture thread

Owns a `Box<dyn PacketSource>`. In the MVP the concrete implementation is
`LivePcapSource`, which wraps `pcap::Capture<pcap::Active>`. The thread loops:
call `next_frame`, forward `Frame` values into the channel, exit on error or
shutdown signal.

### Parser + tracker thread

Receives `Frame` values, extracts the IPv4/IPv6 header and TCP header with
`etherparse`, computes a canonical `ConnectionKey`, and appends the TCP
payload to the appropriate per-direction reassembly buffer. Whenever the
buffer contains a complete TLS record, the record is decoded, and if it is a
handshake record, the enclosed handshake messages are parsed with
`tls-parser`. Progress updates are emitted as `UiEvent::HandshakeUpdated`.

### UI thread (main)

Runs the Ratatui event loop. Merges channel receives with `crossterm` input
events. Rerenders on every event or on a fixed tick interval (used for the
animated arrows in the center panel).

## Data flow guarantees

- The capture thread never blocks on the UI. If the parser channel fills up,
  the capture thread drops packets and increments a counter, visible in the
  UI's status line. Packet capture must not stall.
- The parser thread never allocates unbounded memory. Reassembly buffers are
  capped per connection; oversize buffers are truncated and the connection
  is marked errored.
- The UI thread never performs I/O other than terminal writes and keyboard
  reads.

## Extension points

The MVP already has seams for future features:

| Future feature | Seam already in place |
| --- | --- |
| PCAP file import | `PacketSource` trait; add a `PcapFileSource`. |
| JSON / Markdown export | `HandshakeInfo` derives `serde::Serialize`. |
| TLS 1.2 support | `parser::handshake` dispatches on record type. |
| SSLKEYLOGFILE decryption | Reassembly buffers hold raw ciphertext; a decryption layer can sit between reassembly and handshake parsing. |
| Terminal themes | UI panels take a `&Theme` argument. |
| Plugin architecture | Parser output is a data type, not a callback. |
