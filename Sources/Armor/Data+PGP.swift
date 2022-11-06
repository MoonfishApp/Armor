//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
// Note from Ronald: This is originally Objective C code,
// ported using Swiftify and then rewritten manually

import CommonCrypto
import Foundation


//free(padding_buf)
////paddedData
//let outLen = min(d1.length, d2.length)
//let output = Data(length: Int(outLen))
//let outputBuf = UInt8(output?.mutableBytes ?? 0)
//let d1buf = UInt8(d1.bytes)
//let d2buf = UInt8(d2.bytes)
//var i = 0
////outLen
////output
//var size = 0
//let encoding = value.objCType
//let ptr = calloc(size, 1)
//let data = Data(bytes: &ptr, length: size)
//free(ptr)
////data

let CRC24_POLY = 0x1864cfb
let CRC24_INIT = 0xb704ce

public extension Data {

    ///  Calculates a 16bit sum of all octets, mod 65536
    ///
    ///  - Returns: checksum
    func pgp_Checksum() -> UInt16 {
        var s: UInt32 = 0
        let bytes = self.bytes //as? UnsafePointer<UInt8>
        for i in 0..<count {
            s = UInt32((UInt(s) + UInt(UInt8(bytes[i]))))
        }
        s = s % 65536
        return UInt16(s)
    }

    private func crc_octets(_ octets: [UInt8]) -> Int {

        var crc = CRC24_INIT
        for octet in octets {
            crc ^= Int(octet) << 16
            for _ in 0 ..< 8 {
                crc <<= 1
                if crc & 0x1000000 != 0 {
                    crc ^= CRC24_POLY
                }
            }
        }
        return crc & 0xffffff
    }
    
    func pgp_CRC24() -> UInt32 {
        var crc = UInt32(CRC24_INIT)
        self.withUnsafeBytes { bytes in
            for byte in bytes {
                crc ^= UInt32(byte) << 16
                for _ in 0..<8 {
                    crc <<= 1
                    if crc & 0x1000000 != 0 {
                        crc ^= UInt32(CRC24_POLY)
                    }
                }
            }
        }
        return crc & 0xffffff

    }
    
/*
    func pgp_MD5() -> Data {
        return PGPmd5({ [self] update in
            update?(bytes, count)
        })
    }

    func pgp_SHA1() -> Data {
        return PGPsha1({ [self] update in
            update?(bytes, count)
        })
    }

    func pgp_SHA224() -> Data {
        return PGPsha224({ [self] update in
            update?(bytes, count)
        })
    }

    func pgp_SHA256() -> Data {
        return PGPsha256({ [self] update in
            update?(bytes, count)
        })
    }

    func pgp_SHA384() -> Data {
        return PGPsha384({ [self] update in
            update?(bytes, count)
        })
    }

    func pgp_SHA512() -> Data {
        return PGPsha512({ [self] update in
            update?(bytes, count)
        })
    }

    func pgp_RIPEMD160() -> Data {
        return PGPripemd160({ [self] update in
            update?(bytes, count)
        })
    }

    func pgp_Hashed(with hashAlgorithm: PGPHashAlgorithm) -> Data {
        return PGPCalculateHash(hashAlgorithm, { [self] update in
            update?(bytes, count)
        })
    }

    func pgp_reversed() -> Data {
        let reversed = Data(capacity: count)
        var i = count - 1
        while i >= 0 {
            if let bytes = 0x0 as? UnsafeRawPointer {
                reversed?.append(bytes, length: 1)
            }
            i -= 1
        }
        return reversed!
    }

    func pgp_PKCS5Padded() -> Data {
        // Add PKCS5 padding
        let padding_len = 8 - (count % 8)
        let paddedData = Data(data: self as Data)
    }
*/
}

