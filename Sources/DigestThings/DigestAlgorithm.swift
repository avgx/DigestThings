import CryptoKit
import Foundation

/// A Digest hash algorithm from RFC 7616 §3.2 and §6.1.
///
/// The `-sess` variants hash the server nonce and client nonce into A1 (RFC 7616 §3.4.2).
public enum DigestAlgorithm: String, Sendable, CaseIterable {
    case md5 = "MD5"
    case md5Sess = "MD5-SESS"
    case sha256 = "SHA-256"
    case sha256Sess = "SHA-256-SESS"
    case sha512256 = "SHA-512-256"
    case sha512256Sess = "SHA-512-256-SESS"

    /// Reads the `algorithm` parameter of a challenge. A missing parameter means MD5
    /// (RFC 7616 §3.3). Returns nil for an algorithm this package does not implement.
    public init?(parameter: String?) {
        let name = (parameter ?? "MD5").trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        self.init(rawValue: name)
    }

    /// The name sent in the `algorithm` parameter.
    public var wire: String { rawValue }

    public var isSession: Bool {
        switch self {
        case .md5Sess, .sha256Sess, .sha512256Sess: true
        case .md5, .sha256, .sha512256: false
        }
    }

    /// Higher is stronger. A client should use the strongest one it supports (RFC 7616 §3.7).
    public var preference: Int {
        switch self {
        case .md5, .md5Sess: 1
        case .sha256, .sha256Sess: 2
        case .sha512256, .sha512256Sess: 3
        }
    }

    public func hash(_ data: Data) -> Data {
        switch self {
        case .md5, .md5Sess: Data(Insecure.MD5.hash(data: data))
        case .sha256, .sha256Sess: Data(SHA256.hash(data: data))
        case .sha512256, .sha512256Sess: SHA512_256.hash(data)
        }
    }

    /// Lowercase hex of the hash, as Digest puts it on the wire.
    public func hexHash(_ data: Data) -> String {
        hash(data).map { String(format: "%02x", $0) }.joined()
    }

    public func hexHash(_ string: String) -> String {
        hexHash(Data(string.utf8))
    }
}
