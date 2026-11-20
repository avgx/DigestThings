import Foundation

/// A built `Authorization: Digest ...` value plus what is needed to check the
/// server's `Authentication-Info` for the same request.
public struct DigestAttempt: Sendable, Equatable {
    public var header: String
    public var realm: String
    public var nonce: String
    /// Eight hex digits, exactly as sent in `nc`.
    public var nonceCount: String
    public var cnonce: String
    /// `auth`, `auth-int`, or nil for the RFC 2069 mode without `qop`.
    public var qop: String?
    public var algorithm: DigestAlgorithm
    public var charsetUTF8: Bool
}

/// Computes the Digest `response` and builds the `Authorization` value (RFC 7616 §3.4).
public enum DigestResponse {
    /// When to send the `algorithm` parameter.
    public enum AlgorithmField: Sendable {
        /// Only when the challenge had one. Some cameras reject an `algorithm`
        /// they did not ask for.
        case asChallenged
        /// Always, as RFC 7616 §3.4 recommends.
        case always
    }

    /// Builds the `Authorization` value for one challenge.
    ///
    /// - Parameters:
    ///   - challenge: Challenge parameters with lowercased keys. `realm` and `nonce` are required.
    ///   - nonceCount: How many times this nonce has been used, starting at 1.
    ///   - clientNonce: The `cnonce` value. Use a fresh random value per request.
    ///   - entityBody: The exact request body, used only for `qop=auth-int`.
    public static func authorization(
        credentials: DigestCredentials,
        method: String,
        uri: String,
        challenge: [String: String],
        nonceCount: UInt32,
        clientNonce: String,
        entityBody: Data = Data(),
        algorithmField: AlgorithmField = .asChallenged
    ) throws -> DigestAttempt {
        guard let realm = challenge["realm"], let nonce = challenge["nonce"] else {
            throw DigestError.invalidChallenge
        }
        guard let algorithm = DigestAlgorithm(parameter: challenge["algorithm"]) else {
            throw DigestError.unsupportedAlgorithm(challenge["algorithm"] ?? "")
        }
        let qop = try selectQualityOfProtection(challenge["qop"])

        let charsetUTF8 = challenge["charset"]?.caseInsensitiveCompare("UTF-8") == .orderedSame
        let credentials = credentials.normalized(charsetUTF8: charsetUTF8)
        let userhash = challenge["userhash"]?.lowercased() == "true"
        let nc = String(format: "%08x", nonceCount)

        let ha1 = sessionKey(
            algorithm: algorithm,
            credentials: credentials,
            realm: realm,
            nonce: nonce,
            cnonce: clientNonce
        )
        let ha2: String
        if qop == "auth-int" {
            ha2 = algorithm.hexHash("\(method):\(uri):\(algorithm.hexHash(entityBody))")
        } else {
            ha2 = algorithm.hexHash("\(method):\(uri)")
        }
        let response: String
        if let qop {
            response = algorithm.hexHash("\(ha1):\(nonce):\(nc):\(clientNonce):\(qop):\(ha2)")
        } else {
            response = algorithm.hexHash("\(ha1):\(nonce):\(ha2)")
        }

        let wireUsername = userhash
            ? algorithm.hexHash("\(credentials.username):\(realm)")
            : credentials.username
        var fields = [
            "username=\"\(DigestHeader.quote(wireUsername))\"",
            "realm=\"\(DigestHeader.quote(realm))\"",
            "nonce=\"\(DigestHeader.quote(nonce))\"",
            "uri=\"\(DigestHeader.quote(uri))\"",
            "response=\"\(response)\"",
        ]
        if algorithmField == .always || challenge["algorithm"] != nil {
            fields.append("algorithm=\(algorithm.wire)")
        }
        if let opaque = challenge["opaque"] {
            fields.append("opaque=\"\(DigestHeader.quote(opaque))\"")
        }
        if let qop {
            fields.append("qop=\(qop)")
            fields.append("nc=\(nc)")
            fields.append("cnonce=\"\(clientNonce)\"")
        } else if algorithm.isSession {
            fields.append("cnonce=\"\(clientNonce)\"")
        }
        if userhash {
            fields.append("userhash=true")
        }

        return DigestAttempt(
            header: "Digest " + fields.joined(separator: ", "),
            realm: realm,
            nonce: nonce,
            nonceCount: nc,
            cnonce: clientNonce,
            qop: qop,
            algorithm: algorithm,
            charsetUTF8: charsetUTF8
        )
    }

    /// A random 16-byte client nonce in lowercase hex.
    public static func makeClientNonce() -> String {
        var generator = SystemRandomNumberGenerator()
        return (0..<16).map { _ in
            String(format: "%02x", UInt8.random(in: .min ... .max, using: &generator))
        }.joined()
    }

    /// Prefers `auth`, then `auth-int`. Nil when the challenge has no `qop`.
    static func selectQualityOfProtection(_ value: String?) throws -> String? {
        guard let value else { return nil }
        let options = value.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
        if options.contains("auth") { return "auth" }
        if options.contains("auth-int") { return "auth-int" }
        throw DigestError.unsupportedQualityOfProtection
    }

    /// HA1 from RFC 7616 §3.4.2, with the `-sess` step when the algorithm needs it.
    static func sessionKey(
        algorithm: DigestAlgorithm,
        credentials: DigestCredentials,
        realm: String,
        nonce: String,
        cnonce: String
    ) -> String {
        var ha1 = algorithm.hexHash("\(credentials.username):\(realm):\(credentials.password)")
        if algorithm.isSession {
            ha1 = algorithm.hexHash("\(ha1):\(nonce):\(cnonce)")
        }
        return ha1
    }
}
