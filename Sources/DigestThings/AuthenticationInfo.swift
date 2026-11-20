import Foundation

/// A parsed `Authentication-Info` value (RFC 7616 §3.5).
///
/// The server sends it after a successful Digest request. `rspauth` proves the
/// server knows the password too. `nextnonce` is the nonce to use next.
public struct AuthenticationInfo: Sendable, Equatable {
    public var nextnonce: String?
    public var qop: String?
    public var rspauth: String?
    public var cnonce: String?
    public var nc: String?

    public init(nextnonce: String? = nil, qop: String? = nil, rspauth: String? = nil, cnonce: String? = nil, nc: String? = nil) {
        self.nextnonce = nextnonce
        self.qop = qop
        self.rspauth = rspauth
        self.cnonce = cnonce
        self.nc = nc
    }

    /// Throws ``DigestError/invalidAuthenticationInfo`` when the value is malformed
    /// or has neither `rspauth` nor `nextnonce`.
    public init(parsing header: String) throws {
        guard let parameters = try? DigestHeader.parameters(header),
              parameters["rspauth"] != nil || parameters["nextnonce"] != nil
        else {
            throw DigestError.invalidAuthenticationInfo
        }
        self.init(
            nextnonce: parameters["nextnonce"],
            qop: parameters["qop"],
            rspauth: parameters["rspauth"],
            cnonce: parameters["cnonce"],
            nc: parameters["nc"]
        )
    }

    /// Checks this reply against the request that was sent.
    ///
    /// Echoed `qop`, `cnonce` and `nc` must match the attempt. When `rspauth` is present
    /// it must equal the expected value, where A2 is `":" + uri` with no method or body
    /// (RFC 7616 §3.5, RFC 2617 §3.2.3). A reply with only `nextnonce` passes.
    ///
    /// Throws ``DigestError/authenticationInfoMismatch`` on a mismatch and
    /// ``DigestError/invalidAuthenticationInfo`` when `rspauth` comes without `qop`.
    public func verify(attempt: DigestAttempt, uri: String, credentials: DigestCredentials) throws {
        if let qop, qop.lowercased() != attempt.qop?.lowercased() {
            throw DigestError.authenticationInfoMismatch
        }
        if let cnonce, cnonce != attempt.cnonce {
            throw DigestError.authenticationInfoMismatch
        }
        if let nc, nc.lowercased() != attempt.nonceCount {
            throw DigestError.authenticationInfoMismatch
        }
        guard let rspauth else { return }
        guard let qop = attempt.qop, self.qop != nil else {
            throw DigestError.invalidAuthenticationInfo
        }

        let algorithm = attempt.algorithm
        let ha1 = DigestResponse.sessionKey(
            algorithm: algorithm,
            credentials: credentials.normalized(charsetUTF8: attempt.charsetUTF8),
            realm: attempt.realm,
            nonce: attempt.nonce,
            cnonce: attempt.cnonce
        )
        let ha2 = algorithm.hexHash(":\(uri)")
        let expected = algorithm.hexHash("\(ha1):\(attempt.nonce):\(attempt.nonceCount):\(attempt.cnonce):\(qop):\(ha2)")
        guard rspauth.lowercased() == expected else {
            throw DigestError.authenticationInfoMismatch
        }
    }
}
