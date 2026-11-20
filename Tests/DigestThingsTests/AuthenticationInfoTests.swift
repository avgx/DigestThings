import DigestThings
import Foundation
import Testing

@Suite("Authentication-Info (RFC 7616 §3.5)")
struct AuthenticationInfoTests {
    let credentials = DigestCredentials(username: "admin", password: "secret")
    let uri = "/onvif/device_service"

    func attempt(algorithm: String = "MD5") throws -> DigestAttempt {
        try DigestResponse.authorization(
            credentials: credentials,
            method: "POST",
            uri: uri,
            challenge: ["realm": "cam", "nonce": "n1", "qop": "auth", "algorithm": algorithm],
            nonceCount: 1,
            clientNonce: "fixed-cnonce"
        )
    }

    func rspauth(_ algorithm: DigestAlgorithm) -> String {
        var ha1 = algorithm.hexHash("admin:cam:secret")
        if algorithm.isSession {
            ha1 = algorithm.hexHash("\(ha1):n1:fixed-cnonce")
        }
        let ha2 = algorithm.hexHash(":\(uri)")
        return algorithm.hexHash("\(ha1):n1:00000001:fixed-cnonce:auth:\(ha2)")
    }

    @Test func parsesAllFields() throws {
        let info = try AuthenticationInfo(parsing: #"qop=auth, rspauth="abc", cnonce="c", nc=00000001, nextnonce="n2""#)
        #expect(info == AuthenticationInfo(nextnonce: "n2", qop: "auth", rspauth: "abc", cnonce: "c", nc: "00000001"))
    }

    @Test func rejectsValuesWithoutRspauthOrNextnonce() {
        #expect(throws: DigestError.invalidAuthenticationInfo) { try AuthenticationInfo(parsing: "qop=auth") }
        #expect(throws: DigestError.invalidAuthenticationInfo) { try AuthenticationInfo(parsing: "garbage") }
    }

    @Test(arguments: [DigestAlgorithm.md5, .sha256, .sha512256, .sha256Sess])
    func acceptsTheCorrectRspauth(algorithm: DigestAlgorithm) throws {
        let attempt = try attempt(algorithm: algorithm.wire)
        let info = try AuthenticationInfo(
            parsing: "qop=auth, rspauth=\"\(rspauth(algorithm))\", cnonce=\"fixed-cnonce\", nc=00000001, nextnonce=\"n2\""
        )
        try info.verify(attempt: attempt, uri: uri, credentials: credentials)
    }

    @Test func rejectsAWrongRspauth() throws {
        let info = try AuthenticationInfo(parsing: #"qop=auth, rspauth="deadbeef", cnonce="fixed-cnonce", nc=00000001"#)
        #expect(throws: DigestError.authenticationInfoMismatch) {
            try info.verify(attempt: attempt(), uri: uri, credentials: credentials)
        }
    }

    @Test func rejectsWrongEchoes() throws {
        let attempt = try attempt()
        let good = rspauth(.md5)
        for header in [
            "qop=auth, rspauth=\"\(good)\", cnonce=\"other\", nc=00000001",
            "qop=auth, rspauth=\"\(good)\", cnonce=\"fixed-cnonce\", nc=00000002",
            "qop=auth-int, rspauth=\"\(good)\", cnonce=\"fixed-cnonce\", nc=00000001",
            "nextnonce=\"n2\", cnonce=\"other\"",
        ] {
            let info = try AuthenticationInfo(parsing: header)
            #expect(throws: DigestError.authenticationInfoMismatch) {
                try info.verify(attempt: attempt, uri: uri, credentials: credentials)
            }
        }
    }

    @Test func rspauthWithoutQopIsInvalid() throws {
        let info = try AuthenticationInfo(parsing: #"rspauth="deadbeef", cnonce="fixed-cnonce", nc=00000001"#)
        #expect(throws: DigestError.invalidAuthenticationInfo) {
            try info.verify(attempt: attempt(), uri: uri, credentials: credentials)
        }
    }

    @Test func nextnonceAlonePasses() throws {
        let info = try AuthenticationInfo(parsing: #"nextnonce="n-next""#)
        try info.verify(attempt: attempt(), uri: uri, credentials: credentials)
        #expect(info.nextnonce == "n-next")
    }
}
