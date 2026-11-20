import Foundation

/// User name and password for Digest authentication.
public struct DigestCredentials: Sendable, Equatable {
    public var username: String
    public var password: String

    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }

    /// With `charset=UTF-8` both values are put into Unicode Normalization Form C
    /// before hashing (RFC 7616 §4, Unicode UAX #15). Otherwise they are used as is.
    public func normalized(charsetUTF8: Bool) -> DigestCredentials {
        guard charsetUTF8 else { return self }
        return DigestCredentials(
            username: username.precomposedStringWithCanonicalMapping,
            password: password.precomposedStringWithCanonicalMapping
        )
    }
}
