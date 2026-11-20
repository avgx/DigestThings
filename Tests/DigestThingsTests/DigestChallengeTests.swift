import DigestThings
import Foundation
import Testing

@Suite("WWW-Authenticate parsing and selection (RFC 7235, RFC 7616 §3.7)")
struct DigestChallengeTests {
    @Test func splitsChallengesAcrossSchemesAndQuotedCommas() {
        let split = DigestHeader.splitChallenges(
            "Basic realm=\"cam\", Digest realm=\"a\", nonce=\"n1\", qop=\"auth\", Digest realm=\"b, x\", nonce=\"n2\", algorithm=SHA-256"
        )
        #expect(split.count == 3)
        #expect(split[0].hasPrefix("Basic"))
        #expect(split[1].hasPrefix("Digest"))
        #expect(split[2].hasPrefix("Digest"))
        #expect(split[2].contains("realm=\"b, x\""))
        #expect(split[2].contains("algorithm=SHA-256"))
    }

    @Test func parsesQuotedAndEscapedValues() throws {
        let challenge = try DigestChallenge(#"Digest Realm="a \"b\" c", nonce=n1, qop="auth,auth-int", stale=TRUE"#)
        #expect(challenge.realm == #"a "b" c"#)
        #expect(challenge.nonce == "n1")
        #expect(challenge.parameters["qop"] == "auth,auth-int")
        #expect(challenge.isStale)
        #expect(challenge.algorithm == .md5)
    }

    @Test func recognizesTheDigestSchemeOnly() {
        #expect(DigestHeader.isDigestChallenge("Digest realm=\"r\""))
        #expect(DigestHeader.isDigestChallenge("  digest realm=\"r\""))
        #expect(DigestHeader.isDigestChallenge("DIGEST"))
        #expect(!DigestHeader.isDigestChallenge("Digestive realm=\"r\""))
        #expect(!DigestHeader.isDigestChallenge("Basic realm=\"r\""))
    }

    @Test func rejectsChallengesWithoutRealmOrNonce() {
        #expect(throws: DigestError.invalidChallenge) { try DigestChallenge("Digest realm=\"r\"") }
        #expect(throws: DigestError.missingDigestChallenge) { try DigestChallenge("Basic realm=\"r\"") }
        #expect(throws: DigestError.invalidChallenge) { try DigestChallenge("Digest realm=\"r\", nonce") }
    }

    @Test func selectsTheStrongestSupportedAlgorithm() throws {
        let headers = [
            #"Digest algorithm=MD5, realm="intellect", qop="auth", nonce="n-md5""#,
            #"Digest algorithm=SHA-512-256, realm="intellect", qop="auth", nonce="n-512""#,
            #"Digest algorithm=SHA-256, realm="intellect", qop="auth", nonce="n-256""#,
            #"Digest realm="intellect", nonce="n-default""#,
        ]
        let best = try DigestChallenge.strongest(in: headers)
        #expect(best.algorithm == .sha512256)
        #expect(best.nonce == "n-512")
    }

    @Test func firstChallengeWinsATie() throws {
        let best = try DigestChallenge.strongest(in: [
            "Digest realm=\"cam\", nonce=\"first\", algorithm=SHA-256",
            "Digest realm=\"cam\", nonce=\"second\", algorithm=SHA-256-sess",
        ])
        #expect(best.nonce == "first")
    }

    @Test func skipsUnknownAlgorithmsAndUsesAWeakerSupportedOne() throws {
        let best = try DigestChallenge.strongest(in: [
            "Digest realm=\"cam\", nonce=\"n-weak\", qop=\"auth\", algorithm=MD5",
            "Digest realm=\"cam\", nonce=\"n-unsupported\", qop=\"auth\", algorithm=SHA-512",
        ])
        #expect(best.algorithm == .md5)
        #expect(best.nonce == "n-weak")
    }

    @Test func reportsWhyNoChallengeWasSelected() {
        #expect(throws: DigestError.unsupportedAlgorithm("SHA-512")) {
            try DigestChallenge.strongest(in: ["Digest realm=\"cam\", nonce=\"n1\", algorithm=SHA-512"])
        }
        #expect(throws: DigestError.missingDigestChallenge) {
            try DigestChallenge.strongest(in: ["Basic realm=\"cam\""])
        }
        #expect(throws: DigestError.invalidChallenge) {
            try DigestChallenge.strongest(in: ["Digest realm=\"cam\""])
        }
    }

    @Test func filtersCandidates() throws {
        let headers = [
            "Digest realm=\"cam\", nonce=\"fresh\", algorithm=SHA-256",
            "Digest realm=\"cam\", nonce=\"stale\", algorithm=MD5, stale=true",
        ]
        let stale = try DigestChallenge.strongest(in: headers, where: \.isStale)
        #expect(stale.nonce == "stale")
    }

    @Test func listsAllWellFormedChallenges() {
        let all = DigestChallenge.all(in: [
            "Basic realm=\"cam\", Digest realm=\"a\", nonce=\"n1\"",
            "Digest realm=\"b\"",
            "Digest realm=\"c\", nonce=\"n3\", algorithm=SHA-3",
        ])
        #expect(all.map(\.realm) == ["a", "c"])
        #expect(all[1].algorithm == nil)
    }

    @Test func algorithmNamesAreCaseInsensitive() {
        #expect(DigestAlgorithm(parameter: "sha-256") == .sha256)
        #expect(DigestAlgorithm(parameter: " md5-sess ") == .md5Sess)
        #expect(DigestAlgorithm(parameter: nil) == .md5)
        #expect(DigestAlgorithm(parameter: "SHA-512") == nil)
    }
}
