# What a passive observer can and cannot see

TLS 1.3 was designed with an explicit goal: leak as little information as
possible on the wire. `seehandshake` is a passive observer. It captures
packets but has no access to session keys, so a large portion of a TLS 1.3
handshake is opaque to it. This document is honest about what that means.

## The handshake, in order (diagram steps)

1. **`ClientHello`** (① client → server): sent in the clear.
2. **`ServerHello`** (② server → client): sent in the clear.
3. **`ChangeCipherSpec`**: a legacy marker, in the clear (TLS 1.3 keeps it
   only for middlebox compatibility).
4. **`Certificate`** (③ server → client): an encrypted flight containing
   `EncryptedExtensions`, `Certificate`, and `CertificateVerify`.
5. **`ClientFinished`** (④ client → server): encrypted.
6. **`ServerFinished`** (⑤ server → client): encrypted.

Everything from step 4 onward is protected under *handshake traffic keys*
derived via HKDF from the shared secret computed by the ephemeral key exchange
in steps 1 and 2. Without one of the two private ephemeral keys, or without
the derived traffic secret exported via `SSLKEYLOGFILE`, a passive observer
cannot decrypt these records.

## What `seehandshake` extracts

From **`ClientHello`** (plaintext):

- TLS version(s) offered (from the `supported_versions` extension)
- Cipher suites offered
- SNI (Server Name Indication, from the `server_name` extension)
- ALPN protocols offered (from the `application_layer_protocol_negotiation`
  extension)
- Supported groups (curves) offered
- Key share group(s): the group(s) for which the client actually sent a
  public key

From **`ServerHello`** (plaintext):

- TLS version selected
- Cipher suite selected
- Key share group selected

For post-`ServerHello` messages, `seehandshake` observes the *encrypted record
boundaries*. It can tell you that the server sent, for example, three
application-data records after the ServerHello, and infers stage progression
from that pattern. Field values inside those records (certificate Subject,
Issuer, selected ALPN, etc.) are displayed as `encrypted (TLS 1.3)`.

## What would make more visible?

Three options exist, and are on the roadmap:

1. **`SSLKEYLOGFILE` decryption**. Most browsers, `curl`, and the Rustls /
   OpenSSL / BoringSSL client libraries can export handshake secrets to a
   log file at the request of the operator. `seehandshake` could read that
   file, derive the handshake traffic keys, and decrypt the remaining
   records. This does not compromise anyone else's traffic. It is the
   operator opting to reveal *their own* connection.
2. **TLS 1.2 support**. In TLS 1.2, the certificate is sent in the clear.
   Adding a TLS 1.2 code path lets `seehandshake` display certificate
   Subject/Issuer for TLS 1.2 connections without any decryption.
3. **Active MITM**. Deliberately out of scope. `seehandshake` is a passive
   observer and will remain so.

## Why does the tool bother showing encrypted stages at all?

Because the *shape* of the handshake is itself educational. Seeing the client
send one record, the server respond with an encrypted certificate flight and
Finished message, and then application data begin to flow, teaches the reader
something real about how TLS 1.3 works, even without the field values inside.
`seehandshake` labels these clearly rather than pretending it has decrypted them.

## How the record timeline labels encrypted records

The middle **Handshake** pane shows every TLS record observed on the wire
in order. Plaintext handshake records (`ClientHello`, `ServerHello`,
`HelloRetryRequest`) are decoded field by field. Arrowing through a
record surfaces the per-section educational breakdown in the right pane.
Encrypted records (outer type `application_data` sent *during* the
handshake flight) are labeled by their position in the flight rather
than their contents, because a passive observer cannot see inside them.

The heuristic combines *flight position* and *record size*. Payload size
is a strong signal because a bare `Finished` is ~40-60 B (32 B verify_data +
AEAD tag), whereas a certificate chain is at least ~1 KB. Every label is
hedged with the word "likely":

| Direction | Position + size                     | Label                                                                          |
| --------- | ----------------------------------- | ------------------------------------------------------------------------------ |
| S \u{2192} C     | 1st encrypted, < 200 B         | `likely EncryptedExtensions (server fragmented flight)`                        |
| S \u{2192} C     | 1st encrypted, < 800 B         | `likely EncryptedExtensions + Finished (resumed session, no Certificate)`      |
| S \u{2192} C     | 1st encrypted, \u{2265} 800 B         | `likely EncryptedExtensions + Certificate + CertificateVerify + Finished`      |
| S \u{2192} C     | 2nd encrypted, < 120 B         | `likely Finished only`                                                         |
| S \u{2192} C     | 2nd encrypted, \u{2265} 120 B         | `likely Certificate + CertificateVerify + Finished (continued)`                |
| S \u{2192} C     | 3rd+ encrypted                 | `likely NewSessionTicket (post-handshake)`                                     |
| C \u{2192} S     | before any server encrypted    | `likely 0-RTT early data (PSK session resumption)`                             |
| C \u{2192} S     | 1st post-handshake, < 120 B    | `likely Finished only (~53B = 32B verify_data + AEAD tag)`                     |
| C \u{2192} S     | 1st post-handshake, \u{2265} 120 B    | `likely Certificate + CertificateVerify + Finished (client auth / mTLS)`       |
| C \u{2192} S     | 2nd+ post-handshake            | `encrypted application data`                                                   |

These labels are inferences from *flight position*, not from decrypted
content. In particular, a server that fragments its flight differently than
the common OpenSSL/BoringSSL layout will produce misleading labels; the tool
cannot verify. The ciphertext bytes shown alongside each encrypted record are
real, but they are opaque without keys.

Once two consecutive `application_data` records from the client are observed,
the tool assumes bulk transfer has begun and stops appending further records
to the timeline. This keeps the timeline focused on the handshake, the
scope the tool is honest about.

## Attribution is orthogonal to visibility

The Origin row shown next to every connection is *not* derived from anything
in the handshake. It comes from `/proc/net/tcp` and `/proc/*/fd` on the
local machine. It tells you which process opened the socket, but says
nothing about whether the handshake succeeded, was resumed, or offered any
particular cipher. See [`attribution.md`](attribution.md) for the mechanism
and its limits (notably: browsers give you the process, not the user
action).
