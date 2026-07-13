# Test Fixtures

Binary captures of complete TLS 1.3 records used by the integration tests.

| File | Source | Contents |
|---|---|---|
| `client_hello_tls13.bin` | RFC 8448 §3, "Simple 1-RTT Handshake" | A single `TLSPlaintext` record wrapping a `ClientHello` for SNI `server`. |
| `server_hello_tls13.bin` | RFC 8448 §3, "Simple 1-RTT Handshake" | A single `TLSPlaintext` record wrapping the matching `ServerHello`. |

RFC 8448 is the IETF's normative reference for TLS 1.3 example traces, so
these fixtures are unambiguously well-formed and free of ambiguity about
what fields the parser should extract.

## Reproducibility

The two files are byte-for-byte copies of the record bytes printed in
RFC 8448 §3. Their SHA-256 digests are recorded here so drift is detectable:

```
f0d7b61e8a0f97ff2cec5a1873fe88e7b907ee8d7cd2d22eefed8c4349f154b8  client_hello_tls13.bin
456a0e73ad98ac28618a7f8a55e2b23a2397d571d15581f539219fd1bacf2e69  server_hello_tls13.bin
```
