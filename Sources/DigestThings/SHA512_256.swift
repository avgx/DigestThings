import Foundation

/// SHA-512/256 from FIPS 180-4.
///
/// It runs the SHA-512 compression function with its own initial hash value
/// (FIPS 180-4 §5.3.6.2) and keeps the first 256 bits. It is not the same as
/// the first 32 bytes of a plain SHA-512 hash. Apple CryptoKit does not offer it.
public enum SHA512_256 {
    /// Size of the result in bytes.
    public static let byteCount = 32

    public static func hash(_ data: Data) -> Data {
        var state = initialHash
        let messageBitLength = UInt64(data.count) &* 8

        var message = [UInt8](data)
        message.append(0x80)
        while message.count % 128 != 112 {
            message.append(0)
        }
        // The length field is 128 bits. The high 64 bits are always zero here.
        message.append(contentsOf: [UInt8](repeating: 0, count: 8))
        for shift in stride(from: 56, through: 0, by: -8) {
            message.append(UInt8(truncatingIfNeeded: messageBitLength >> UInt64(shift)))
        }

        var w = [UInt64](repeating: 0, count: 80)
        for blockStart in stride(from: 0, to: message.count, by: 128) {
            for t in 0..<16 {
                var word: UInt64 = 0
                for byte in 0..<8 {
                    word = (word << 8) | UInt64(message[blockStart + t * 8 + byte])
                }
                w[t] = word
            }
            for t in 16..<80 {
                w[t] = smallSigma1(w[t - 2]) &+ w[t - 7] &+ smallSigma0(w[t - 15]) &+ w[t - 16]
            }

            var a = state[0], b = state[1], c = state[2], d = state[3]
            var e = state[4], f = state[5], g = state[6], h = state[7]
            for t in 0..<80 {
                let t1 = h &+ bigSigma1(e) &+ ((e & f) ^ (~e & g)) &+ roundConstants[t] &+ w[t]
                let t2 = bigSigma0(a) &+ ((a & b) ^ (a & c) ^ (b & c))
                h = g
                g = f
                f = e
                e = d &+ t1
                d = c
                c = b
                b = a
                a = t1 &+ t2
            }
            state[0] &+= a
            state[1] &+= b
            state[2] &+= c
            state[3] &+= d
            state[4] &+= e
            state[5] &+= f
            state[6] &+= g
            state[7] &+= h
        }

        var digest = Data(capacity: byteCount)
        for word in state.prefix(4) {
            for shift in stride(from: 56, through: 0, by: -8) {
                digest.append(UInt8(truncatingIfNeeded: word >> UInt64(shift)))
            }
        }
        return digest
    }

    private static func rotateRight(_ value: UInt64, _ count: UInt64) -> UInt64 {
        (value >> count) | (value << (64 - count))
    }

    private static func bigSigma0(_ x: UInt64) -> UInt64 {
        rotateRight(x, 28) ^ rotateRight(x, 34) ^ rotateRight(x, 39)
    }

    private static func bigSigma1(_ x: UInt64) -> UInt64 {
        rotateRight(x, 14) ^ rotateRight(x, 18) ^ rotateRight(x, 41)
    }

    private static func smallSigma0(_ x: UInt64) -> UInt64 {
        rotateRight(x, 1) ^ rotateRight(x, 8) ^ (x >> 7)
    }

    private static func smallSigma1(_ x: UInt64) -> UInt64 {
        rotateRight(x, 19) ^ rotateRight(x, 61) ^ (x >> 6)
    }

    /// FIPS 180-4 §5.3.6.2.
    private static let initialHash: [UInt64] = [
        0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
        0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
    ]

    /// FIPS 180-4 §4.2.3.
    private static let roundConstants: [UInt64] = [
        0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
        0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
        0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
        0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
        0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
        0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
        0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
        0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
        0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
        0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
        0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
    ]
}
