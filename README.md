# DigestThings

SwiftPM library for HTTP and RTSP Digest authentication. It builds the `Authorization: Digest ...` header for a request and checks the `Authentication-Info` header the server sends back.

It has no dependencies outside Apple's SDK.

## What it does

- Reads `WWW-Authenticate` headers. One header can hold several challenges, for example `Basic` and two `Digest` offers with different algorithms.
- Picks the strongest Digest challenge it can answer, and skips algorithms it does not know.
- Computes the Digest `response` and builds the `Authorization` value.
- Checks `Authentication-Info`: the echoed `qop`, `cnonce` and `nc`, and the server proof `rspauth`.
- Hashes with MD5, SHA-256 and SHA-512/256.

## What it does not do

- No networking. You send the requests.
- No session policy. Your code decides when to retry after a `401`, when to send credentials without waiting for a challenge, how to count nonce use, and what to do with `stale=true` or `nextnonce`. Different protocols need different rules.
- No Basic authentication. It is one line of Base64 and does not need a library.

## Why it exists

Apple CryptoKit has MD5 and SHA-256, but not SHA-512/256. Cameras and servers that follow RFC 7616 may offer SHA-512/256, and it is the strongest Digest algorithm. Before this package, supporting it meant depending on [swift-crypto](https://github.com/apple/swift-crypto) for one hash function. DigestThings implements SHA-512/256 itself, in about a hundred lines, and checks it against the FIPS test vectors.

The Digest code was also copied between projects. It now lives in one place.

## Standards

| Standard | What this package uses from it |
|---|---|
| [RFC 7616](https://www.rfc-editor.org/rfc/rfc7616) | HTTP Digest Access Authentication, the main spec. Algorithms, `qop=auth` and `auth-int`, `-sess` variants, `userhash`, `charset=UTF-8`, `opaque`, `Authentication-Info`, and the rule to use the strongest algorithm (§3.7). |
| [RFC 2617](https://www.rfc-editor.org/rfc/rfc2617) | The older Digest spec. MD5, and the `rspauth` rule where A2 is `":" + uri` (§3.2.3). Many cameras still follow it. |
| [RFC 2069](https://www.rfc-editor.org/rfc/rfc2069) | The original Digest mode without `qop`. The response has no `nc` or `cnonce`. Old devices still send such challenges. |
| [RFC 7235](https://www.rfc-editor.org/rfc/rfc7235) | `WWW-Authenticate` syntax: several challenges in one header, quoted values with commas and escapes. |
| [RFC 2326 §12.44](https://www.rfc-editor.org/rfc/rfc2326#section-12.44), [RFC 7826](https://www.rfc-editor.org/rfc/rfc7826) | RTSP 1.0 and 2.0 reuse HTTP authentication as is. |
| [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) | SHA-256 (via CryptoKit) and SHA-512/256 (§5.3.6, implemented here). SHA-512/256 has its own start values, so it is not the first half of a SHA-512 hash. |
| [RFC 1321](https://www.rfc-editor.org/rfc/rfc1321) | MD5, via CryptoKit. |
| [Unicode UAX #15](https://unicode.org/reports/tr15/) | Normalization Form C. With `charset=UTF-8`, RFC 7616 §4 asks to normalize the user name and password before hashing, so `é` typed two different ways gives the same result. |

The SHA-512/256 example in RFC 7616 §3.9.2 prints wrong values. The tests use the corrected values from [Errata 4897](https://www.rfc-editor.org/errata/eid4897).

## Supported algorithms

| `algorithm` | Strength | Notes |
|---|---|---|
| `SHA-512-256`, `SHA-512-256-sess` | 3 (strongest) | SHA-512/256 implemented in this package. |
| `SHA-256`, `SHA-256-sess` | 2 | CryptoKit. |
| `MD5`, `MD5-sess` | 1 | CryptoKit. Also used when a challenge has no `algorithm`. |

When a server offers several challenges, the strongest one wins. On a tie, the first one wins. A challenge with an unknown algorithm (for example `SHA-512`) is skipped, so a weaker supported one is still used. Names are case-insensitive.

## SwiftPM

```swift
.package(url: "https://github.com/avgx/DigestThings.git", from: "0.1.0")
```

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "DigestThings", package: "DigestThings"),
    ]
),
```

Platforms: iOS 15, macOS 13, tvOS 15, watchOS 8, visionOS 1.

## Usage

```swift
import DigestThings

let credentials = DigestCredentials(username: "admin", password: "secret")

// 1. The server answered 401. Pass every WWW-Authenticate value it sent.
let challenge = try DigestChallenge.strongest(in: wwwAuthenticateValues)

// 2. Build the Authorization header. Count nonce use yourself, starting at 1.
let attempt = try DigestResponse.authorization(
    credentials: credentials,
    method: "DESCRIBE",
    uri: "rtsp://camera/stream",
    challenge: challenge.parameters,
    nonceCount: 1,
    clientNonce: DigestResponse.makeClientNonce()
)
request.setValue(attempt.header, forHTTPHeaderField: "Authorization")

// 3. The server answered 2xx. Check its Authentication-Info, if any.
if let value = response.value(forHTTPHeaderField: "Authentication-Info") {
    let info = try AuthenticationInfo(parsing: value)
    try info.verify(attempt: attempt, uri: "rtsp://camera/stream", credentials: credentials)
    // info.nextnonce, if present, is the nonce for the next request.
}
```

`algorithmField` controls the `algorithm` parameter in the header. The default `.asChallenged` sends it only when the challenge had one, because some cameras reject a header with an `algorithm` they did not ask for. `.always` sends it every time, as RFC 7616 recommends.

Errors are `DigestError` values: no Digest challenge, a malformed challenge, an unsupported algorithm or `qop`, or an `Authentication-Info` that does not match.

## Security notes

- MD5 is weak. It is here because many cameras support nothing else. The strongest offered algorithm is always chosen, so MD5 is used only when the server offers nothing better.
- Digest does not encrypt anything. Use TLS where you can.
- Use a fresh random client nonce for each request. `DigestResponse.makeClientNonce()` returns 16 random bytes in hex.

## License

MIT. See [LICENSE](LICENSE).
