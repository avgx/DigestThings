import CryptoKit
import DigestThings
import Foundation
import Testing

private func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

@Suite("SHA-512/256 (FIPS 180-4)")
struct SHA512_256Tests {
    @Test(arguments: [
        ("", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"),
        ("abc", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461"
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a"
        ),
    ])
    func knownVectors(message: String, expected: String) {
        #expect(hex(SHA512_256.hash(Data(message.utf8))) == expected)
    }

    // Lengths around the padding boundary: 111 bytes fit in one block, 112 need two.
    @Test(arguments: [
        (111, "0239e429f98d0ed61ee8e2a7c30afe98c1c3a80ce5dff62a107e9c538f7632ce"),
        (112, "9216b5303edb66504570bee90e48ea5beaa5e9fe9f760bbd3e0460559fc005f6"),
        (127, "2fe3b2a6ee7e12f6fe4ba82166541ad9b4ed882c493581cbe300d68f3757b778"),
        (128, "b88f97e274f9c1d49f181c8cbd01a9c74930ad055a46ac4499a1d601f1c80bf2"),
        (239, "78d0a1b37aaad84c89fff13cbe3cd3d1025bcdb648268f9102b7e7032bea7d2a"),
    ])
    func paddingBoundaries(length: Int, expected: String) {
        let message = Data(repeating: UInt8(ascii: "a"), count: length)
        #expect(hex(SHA512_256.hash(message)) == expected)
    }

    @Test func isNotTruncatedSHA512() {
        let data = Data("abc".utf8)
        #expect(SHA512_256.hash(data).count == SHA512_256.byteCount)
        #expect(SHA512_256.hash(data) != Data(SHA512.hash(data: data).prefix(SHA512_256.byteCount)))
        #expect(DigestAlgorithm.sha512256.hexHash(data) == hex(SHA512_256.hash(data)))
    }
}
