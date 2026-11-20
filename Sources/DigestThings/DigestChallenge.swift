import Foundation

/// One Digest challenge from a `WWW-Authenticate` value (RFC 7616 §3.3).
public struct DigestChallenge: Sendable, Equatable {
    /// The challenge text as it appeared in the header, scheme included.
    public let text: String
    /// Parameters with lowercased keys and unquoted values.
    public var parameters: [String: String]

    /// Parses one challenge. It must use the Digest scheme and carry `realm` and `nonce`.
    public init(_ text: String) throws {
        guard DigestHeader.isDigestChallenge(text) else {
            throw DigestError.missingDigestChallenge
        }
        let afterScheme = text.drop(while: { $0 == " " || $0 == "\t" }).dropFirst("digest".count)
        let parameters = try DigestHeader.parameters(String(afterScheme))
        guard parameters["realm"] != nil, parameters["nonce"] != nil else {
            throw DigestError.invalidChallenge
        }
        self.text = text
        self.parameters = parameters
    }

    public var realm: String { parameters["realm"] ?? "" }
    public var nonce: String { parameters["nonce"] ?? "" }

    /// Nil when the challenge names an algorithm this package does not implement.
    public var algorithm: DigestAlgorithm? { DigestAlgorithm(parameter: parameters["algorithm"]) }

    /// `stale=true` means the nonce expired but the credentials were fine (RFC 7616 §3.3).
    public var isStale: Bool { parameters["stale"]?.lowercased() == "true" }

    /// Every well-formed Digest challenge in the given `WWW-Authenticate` values, in order.
    public static func all(in headerValues: [String]) -> [DigestChallenge] {
        headerValues
            .flatMap(DigestHeader.splitChallenges)
            .compactMap { try? DigestChallenge($0) }
    }

    /// The strongest supported Digest challenge (RFC 7616 §3.7). Challenges with an
    /// unknown algorithm are skipped, so a weaker supported one is still used. On a tie
    /// the first one wins.
    ///
    /// Throws ``DigestError/missingDigestChallenge`` when there is no Digest challenge,
    /// ``DigestError/unsupportedAlgorithm(_:)`` when none of the offered algorithms is
    /// supported, and ``DigestError/invalidChallenge`` when every Digest challenge is malformed.
    public static func strongest(
        in headerValues: [String],
        where include: (DigestChallenge) -> Bool = { _ in true }
    ) throws -> DigestChallenge {
        var sawDigest = false
        var offered: [String] = []
        var best: (challenge: DigestChallenge, preference: Int)?
        for piece in headerValues.flatMap(DigestHeader.splitChallenges) {
            guard DigestHeader.isDigestChallenge(piece) else { continue }
            sawDigest = true
            guard let challenge = try? DigestChallenge(piece), include(challenge) else { continue }
            guard let algorithm = challenge.algorithm else {
                offered.append((challenge.parameters["algorithm"] ?? "MD5").uppercased())
                continue
            }
            if best == nil || algorithm.preference > best!.preference {
                best = (challenge, algorithm.preference)
            }
        }
        if let best { return best.challenge }
        guard sawDigest else { throw DigestError.missingDigestChallenge }
        guard !offered.isEmpty else { throw DigestError.invalidChallenge }
        throw DigestError.unsupportedAlgorithm(offered.joined(separator: ", "))
    }
}
