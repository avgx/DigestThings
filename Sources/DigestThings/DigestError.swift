import Foundation

/// Why a Digest header could not be built or checked.
public enum DigestError: Error, Equatable, Sendable, LocalizedError {
    /// No `WWW-Authenticate` value uses the Digest scheme.
    case missingDigestChallenge
    /// A Digest challenge is malformed, or it has no `realm` or `nonce`.
    case invalidChallenge
    /// Every Digest challenge names an algorithm this package does not implement.
    /// The value lists the offered algorithms.
    case unsupportedAlgorithm(String)
    /// The challenge offers `qop`, but neither `auth` nor `auth-int`.
    case unsupportedQualityOfProtection
    /// An `Authentication-Info` value is malformed or carries neither `rspauth` nor `nextnonce`.
    case invalidAuthenticationInfo
    /// An `Authentication-Info` value does not match the request that was sent.
    case authenticationInfoMismatch

    public var errorDescription: String? {
        switch self {
        case .missingDigestChallenge:
            "The server did not provide an HTTP Digest challenge"
        case .invalidChallenge:
            "The HTTP Digest challenge is invalid or incomplete"
        case .unsupportedAlgorithm(let algorithm):
            "The HTTP Digest algorithm \(algorithm) is not supported"
        case .unsupportedQualityOfProtection:
            "The HTTP Digest challenge does not offer qop=auth or qop=auth-int"
        case .invalidAuthenticationInfo:
            "The Authentication-Info header is invalid or incomplete"
        case .authenticationInfoMismatch:
            "The Authentication-Info header does not match the authenticated request"
        }
    }
}
