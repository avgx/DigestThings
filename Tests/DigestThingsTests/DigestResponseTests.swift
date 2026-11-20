import DigestThings
import Foundation
import Testing

/// Reads one `key=value` or `key="value"` field from a built header.
func digestField(_ header: String?, _ name: String) -> String? {
    guard let header, header.hasPrefix("Digest ") else { return nil }
    return (try? DigestHeader.parameters(String(header.dropFirst("Digest ".count))))?[name]
}

@Suite("Digest response (RFC 2617, RFC 7616)")
struct DigestResponseTests {
    let user = DigestCredentials(username: "user", password: "pass")

    @Test func rfc2617MD5Vector() throws {
        let attempt = try DigestResponse.authorization(
            credentials: DigestCredentials(username: "Mufasa", password: "Circle Of Life"),
            method: "GET",
            uri: "/dir/index.html",
            challenge: [
                "realm": "testrealm@host.com",
                "qop": "auth,auth-int",
                "nonce": "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                "opaque": "5ccc069c403ebaf9f0171e9517f40e41",
            ],
            nonceCount: 1,
            clientNonce: "0a4f113b"
        )
        #expect(digestField(attempt.header, "username") == "Mufasa")
        #expect(digestField(attempt.header, "response") == "6629fae49393a05397450978507c4ef1")
        #expect(digestField(attempt.header, "qop") == "auth")
        #expect(digestField(attempt.header, "nc") == "00000001")
        #expect(digestField(attempt.header, "cnonce") == "0a4f113b")
        #expect(digestField(attempt.header, "opaque") == "5ccc069c403ebaf9f0171e9517f40e41")
        #expect(!attempt.header.contains("algorithm="))
        #expect(attempt.algorithm == .md5)
    }

    @Test func rfc7616SHA256Vector() throws {
        let attempt = try DigestResponse.authorization(
            credentials: DigestCredentials(username: "Mufasa", password: "Circle of Life"),
            method: "GET",
            uri: "/dir/index.html",
            challenge: [
                "realm": "http-auth@example.org",
                "qop": "auth, auth-int",
                "algorithm": "SHA-256",
                "nonce": "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
                "opaque": "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
            ],
            nonceCount: 1,
            clientNonce: "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
        )
        #expect(digestField(attempt.header, "response") == "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1")
        #expect(digestField(attempt.header, "algorithm") == "SHA-256")
    }

    // RFC 7616 §3.9.2 prints values that do not match SHA-512/256. These are the
    // corrected values from Errata 4897.
    @Test func rfc7616SHA512256UserhashVector() throws {
        let attempt = try DigestResponse.authorization(
            credentials: DigestCredentials(username: "Jäsøn Doe", password: "Secret, or not?"),
            method: "GET",
            uri: "/doe.json",
            challenge: [
                "realm": "api@example.org",
                "qop": "auth",
                "algorithm": "SHA-512-256",
                "nonce": "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK",
                "opaque": "HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS",
                "charset": "UTF-8",
                "userhash": "true",
            ],
            nonceCount: 1,
            clientNonce: "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v"
        )
        #expect(digestField(attempt.header, "username") == "793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b")
        #expect(digestField(attempt.header, "response") == "3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5")
        #expect(digestField(attempt.header, "algorithm") == "SHA-512-256")
        #expect(attempt.header.contains("userhash=true"))
        #expect(attempt.charsetUTF8)
    }

    @Test func md5AndSHA256WithOpaque() throws {
        let md5 = try DigestResponse.authorization(
            credentials: user,
            method: "DESCRIBE",
            uri: "rtsp://host/stream",
            challenge: ["realm": "intellect", "nonce": "abcnonce", "qop": "auth", "algorithm": "MD5", "opaque": "00004823"],
            nonceCount: 1,
            clientNonce: "0a4f113b"
        )
        #expect(digestField(md5.header, "response") == "bb232cfddcf0011d3685c205603ba090")
        #expect(digestField(md5.header, "opaque") == "00004823")

        let sha256 = try DigestResponse.authorization(
            credentials: user,
            method: "DESCRIBE",
            uri: "rtsp://host/stream",
            challenge: ["realm": "intellect", "nonce": "abcnonce", "qop": "auth", "algorithm": "SHA-256"],
            nonceCount: 1,
            clientNonce: "0a4f113b"
        )
        #expect(digestField(sha256.header, "response") == "059fea890a6f4b177dcc93facb8ff441ed1144725fe25e7c4ad6cd33c9e168d7")
    }

    @Test func algorithmFieldFollowsTheChallengeOrIsAlwaysSent() throws {
        let challenge = ["realm": "intellect", "nonce": "abcnonce", "qop": "auth", "opaque": "00004823"]
        let asChallenged = try DigestResponse.authorization(
            credentials: user, method: "DESCRIBE", uri: "rtsp://host/stream",
            challenge: challenge, nonceCount: 1, clientNonce: "0a4f113b"
        )
        #expect(!asChallenged.header.contains("algorithm="))
        #expect(digestField(asChallenged.header, "response") == "bb232cfddcf0011d3685c205603ba090")

        let always = try DigestResponse.authorization(
            credentials: user, method: "DESCRIBE", uri: "rtsp://host/stream",
            challenge: challenge, nonceCount: 1, clientNonce: "0a4f113b", algorithmField: .always
        )
        #expect(digestField(always.header, "algorithm") == "MD5")
        #expect(digestField(always.header, "response") == digestField(asChallenged.header, "response"))
    }

    @Test func sessionAlgorithmsSendCnonceAndHashItIntoHA1() throws {
        let challenge = ["realm": "intellect", "nonce": "abcnonce", "algorithm": "MD5-sess"]
        let first = try DigestResponse.authorization(
            credentials: user, method: "DESCRIBE", uri: "rtsp://host/stream",
            challenge: challenge, nonceCount: 1, clientNonce: "one"
        )
        let second = try DigestResponse.authorization(
            credentials: user, method: "DESCRIBE", uri: "rtsp://host/stream",
            challenge: challenge, nonceCount: 1, clientNonce: "two"
        )
        #expect(digestField(first.header, "algorithm") == "MD5-SESS")
        #expect(digestField(first.header, "cnonce") == "one")
        #expect(digestField(first.header, "qop") == nil)
        #expect(digestField(first.header, "response") != digestField(second.header, "response"))

        let sha = try DigestResponse.authorization(
            credentials: user, method: "DESCRIBE", uri: "rtsp://host/stream",
            challenge: ["realm": "intellect", "nonce": "abcnonce", "algorithm": "SHA-512-256-sess"],
            nonceCount: 1, clientNonce: "one"
        )
        #expect(sha.algorithm == .sha512256Sess)
        #expect(digestField(sha.header, "response")?.count == 64)
    }

    @Test func rfc2069ModeWithoutQop() throws {
        let attempt = try DigestResponse.authorization(
            credentials: user, method: "DESCRIBE", uri: "rtsp://host/stream",
            challenge: ["realm": "cam", "nonce": "n1"], nonceCount: 1, clientNonce: "c"
        )
        let ha1 = DigestAlgorithm.md5.hexHash("user:cam:pass")
        let ha2 = DigestAlgorithm.md5.hexHash("DESCRIBE:rtsp://host/stream")
        #expect(digestField(attempt.header, "response") == DigestAlgorithm.md5.hexHash("\(ha1):n1:\(ha2)"))
        #expect(digestField(attempt.header, "nc") == nil)
        #expect(digestField(attempt.header, "cnonce") == nil)
        #expect(attempt.qop == nil)
    }

    @Test func nfcNormalizationWithUTF8Charset() throws {
        let challenge = ["realm": "camera", "nonce": "nonce", "qop": "auth", "algorithm": "SHA-256", "charset": "UTF-8"]
        let composed = try DigestResponse.authorization(
            credentials: DigestCredentials(username: "caf\u{00E9}", password: "p\u{00E9}ss"),
            method: "POST", uri: "/onvif", challenge: challenge, nonceCount: 1, clientNonce: "fixed"
        )
        let decomposed = try DigestResponse.authorization(
            credentials: DigestCredentials(username: "cafe\u{0301}", password: "pe\u{0301}ss"),
            method: "POST", uri: "/onvif", challenge: challenge, nonceCount: 1, clientNonce: "fixed"
        )
        #expect(composed.header == decomposed.header)
    }

    @Test func authIntCoversTheBody() throws {
        let challenge = ["realm": "camera", "nonce": "nonce-int", "qop": "auth-int", "algorithm": "MD5"]
        let first = try DigestResponse.authorization(
            credentials: user, method: "POST", uri: "/onvif", challenge: challenge,
            nonceCount: 1, clientNonce: "fixed", entityBody: Data("<A/>".utf8)
        )
        let second = try DigestResponse.authorization(
            credentials: user, method: "POST", uri: "/onvif", challenge: challenge,
            nonceCount: 1, clientNonce: "fixed", entityBody: Data("<B/>".utf8)
        )
        #expect(first.header.contains("qop=auth-int"))
        #expect(first.header != second.header)
    }

    @Test func nonceCountIsEightHexDigits() throws {
        let attempt = try DigestResponse.authorization(
            credentials: user, method: "GET", uri: "/",
            challenge: ["realm": "r", "nonce": "n", "qop": "auth"], nonceCount: 0x1a, clientNonce: "c"
        )
        #expect(attempt.nonceCount == "0000001a")
        #expect(digestField(attempt.header, "nc") == "0000001a")
    }

    @Test func quotesSpecialCharactersInValues() throws {
        let attempt = try DigestResponse.authorization(
            credentials: DigestCredentials(username: "a\"b\\c", password: "p"),
            method: "GET", uri: "/", challenge: ["realm": "r", "nonce": "n"], nonceCount: 1, clientNonce: "c"
        )
        #expect(attempt.header.contains(#"username="a\"b\\c""#))
        #expect(digestField(attempt.header, "username") == "a\"b\\c")
    }

    @Test func rejectsUnusableChallenges() {
        #expect(throws: DigestError.unsupportedAlgorithm("SHA-3")) {
            try DigestResponse.authorization(
                credentials: user, method: "GET", uri: "/",
                challenge: ["realm": "r", "nonce": "n", "algorithm": "SHA-3"], nonceCount: 1, clientNonce: "c"
            )
        }
        #expect(throws: DigestError.invalidChallenge) {
            try DigestResponse.authorization(
                credentials: user, method: "GET", uri: "/",
                challenge: ["realm": "r"], nonceCount: 1, clientNonce: "c"
            )
        }
        #expect(throws: DigestError.unsupportedQualityOfProtection) {
            try DigestResponse.authorization(
                credentials: user, method: "GET", uri: "/",
                challenge: ["realm": "r", "nonce": "n", "qop": "auth-conf"], nonceCount: 1, clientNonce: "c"
            )
        }
    }

    @Test func clientNonceIsRandomHex() {
        let first = DigestResponse.makeClientNonce()
        #expect(first.count == 32)
        #expect(first.allSatisfy { $0.isHexDigit })
        #expect(first != DigestResponse.makeClientNonce())
    }
}
