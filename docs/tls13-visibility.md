# What a passive observer can and cannot see

TLS 1.3 was designed with an explicit goal: leak as little information as
possible on the wire. `seehandshake` is a passive observer — it captures
packets but has no access to session keys — so a large portion of a TLS 1.3
handshake is opaque to it. This document is honest about what that means.

## The handshake, in order (diagram steps)

1. **`ClientHello`** (① client → server) — sent in the clear.
2. **`ServerHello`** (② server → client) — sent in the clear.
3. **`ChangeCipherSpec`** — a legacy marker, in the clear (TLS 1.3 keeps it
   only for middlebox compatibility).
4. **`Certificate`** (③ server → client) — an encrypted flight containing
   `EncryptedExtensions`, `Certificate`, and `CertificateVerify`.
5. **`ClientFinished`** (④ client → server) — encrypted.
6. **`ServerFinished`** (⑤ server → client) — encrypted.

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
- Key share group(s) — the group(s) for which the client actually sent a
  public key

From **`ServerHello`** (plaintext):

- TLS version selected
- Cipher suite selected
- Key share group selected

For post-`ServerHello` messages, `seehandshake` observes the *encrypted record
boundaries* — it can tell you that the server sent, for example, three
application-data records after the ServerHello — and infers stage progression
from that pattern. Field values inside those records (certificate Subject,
Issuer, selected ALPN, etc.) are displayed as `encrypted (TLS 1.3)`.

## What would make more visible?

Three options exist, and are on the roadmap:

1. **`SSLKEYLOGFILE` decryption**. Most browsers, `curl`, and the Rustls /
   OpenSSL / BoringSSL client libraries can export handshake secrets to a
   log file at the request of the operator. `seehandshake` could read that
   file, derive the handshake traffic keys, and decrypt the remaining
   records. This does not compromise anyone else's traffic — it is the
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
something real about how TLS 1.3 works — even without the field values inside.
`seehandshake` labels these clearly rather than pretending it has decrypted them.
