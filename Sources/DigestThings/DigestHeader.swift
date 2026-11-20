import Foundation

/// Parsing helpers for `WWW-Authenticate` and `Authentication-Info` values.
///
/// Syntax follows RFC 7235 §2.1 and §4.1: one header value may hold several challenges,
/// and quoted values may contain commas and backslash escapes.
public enum DigestHeader {
    /// Splits one header value into challenges. A token that is not followed by `=`
    /// starts a new challenge. Commas inside quotes stay in the value.
    public static func splitChallenges(_ headerValue: String) -> [String] {
        var challenges: [String] = []
        var current = ""
        var index = headerValue.startIndex
        let value = headerValue
        let end = value.endIndex

        while index < end {
            while index < end, value[index] == "," || value[index] == " " || value[index] == "\t" {
                index = value.index(after: index)
            }
            guard index < end else { break }

            let tokenStart = index
            while index < end, value[index] != "=", value[index] != ",", value[index] != " ", value[index] != "\t" {
                index = value.index(after: index)
            }
            let token = value[tokenStart..<index]

            var peek = index
            while peek < end, value[peek] == " " || value[peek] == "\t" {
                peek = value.index(after: peek)
            }
            if peek < end, value[peek] == "=" {
                if !current.isEmpty { current += ", " }
                current += token
                current += "="
                index = value.index(after: peek)
                if index < end, value[index] == "\"" {
                    current.append("\"")
                    index = value.index(after: index)
                    while index < end {
                        let character = value[index]
                        index = value.index(after: index)
                        current.append(character)
                        if character == "\\", index < end {
                            current.append(value[index])
                            index = value.index(after: index)
                        } else if character == "\"" {
                            break
                        }
                    }
                } else {
                    let valueStart = index
                    while index < end, value[index] != "," {
                        index = value.index(after: index)
                    }
                    current += value[valueStart..<index].trimmingCharacters(in: .whitespaces)
                }
            } else {
                if !current.isEmpty { challenges.append(current) }
                current = String(token)
            }
        }
        if !current.isEmpty { challenges.append(current) }
        return challenges
    }

    /// True when the challenge scheme is `Digest`, in any letter case.
    public static func isDigestChallenge(_ challenge: String) -> Bool {
        var index = challenge.startIndex
        while index < challenge.endIndex, challenge[index] == " " || challenge[index] == "\t" {
            index = challenge.index(after: index)
        }
        let rest = challenge[index...]
        guard rest.lowercased().hasPrefix("digest") else { return false }
        let after = rest.index(rest.startIndex, offsetBy: "digest".count)
        return after == rest.endIndex || rest[after] == " " || rest[after] == "\t" || rest[after] == ","
    }

    /// Parses `key=value, key="quoted value"` pairs. Keys are lowercased.
    /// Throws ``DigestError/invalidChallenge`` when a pair has no `=` or an empty key.
    public static func parameters(_ value: String) throws -> [String: String] {
        var fields: [String: String] = [:]
        var index = value.startIndex
        while index < value.endIndex {
            while index < value.endIndex, value[index] == "," || value[index].isWhitespace {
                index = value.index(after: index)
            }
            guard index < value.endIndex else { break }

            let keyStart = index
            while index < value.endIndex, value[index] != "=", value[index] != "," {
                index = value.index(after: index)
            }
            guard index < value.endIndex, value[index] == "=" else {
                throw DigestError.invalidChallenge
            }
            let key = value[keyStart..<index].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            index = value.index(after: index)
            guard !key.isEmpty else { throw DigestError.invalidChallenge }

            let fieldValue: String
            if index < value.endIndex, value[index] == "\"" {
                index = value.index(after: index)
                var decoded = ""
                while index < value.endIndex {
                    let character = value[index]
                    index = value.index(after: index)
                    if character == "\\", index < value.endIndex {
                        decoded.append(value[index])
                        index = value.index(after: index)
                    } else if character == "\"" {
                        break
                    } else {
                        decoded.append(character)
                    }
                }
                fieldValue = decoded
            } else {
                let start = index
                while index < value.endIndex, value[index] != "," {
                    index = value.index(after: index)
                }
                fieldValue = value[start..<index].trimmingCharacters(in: .whitespacesAndNewlines)
            }
            fields[key] = fieldValue
        }
        return fields
    }

    /// Escapes `\` and `"` for a quoted-string value (RFC 7230 §3.2.6).
    public static func quote(_ value: String) -> String {
        value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }
}
