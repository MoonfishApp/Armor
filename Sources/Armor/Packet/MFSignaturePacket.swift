//
//  MFSignaturePacket.swift
//  
//
//  Created by Ronald Mannak on 5/5/22.
//

import Foundation

/**
    A Signature packet
    https://tools.ietf.org/html/rfc4880#section-5.2
    Example:
    https://didisoft.com/java-openpgp/examples/sign/
 */
public struct MFSignaturePacket: Packetable {
    
    public var tag:PacketTag {
        return .signature
    }
    
    /**
        Only support version 4 signatures
    */
    public let supportedVersion = 4
    
    public var kind:Signature.Kind
    public var chainID: UInt8 // Replacing publicKeyAlgorithm in original Signature packet
    public var hashAlgorithm:Signature.HashAlgorithm
    public var hashedSubpacketables:[SignatureSubpacketable]
    public var unhashedSubpacketables:[SignatureSubpacketable]
    public var signature:Data
    public var leftTwoHashBytes:[UInt8]
    
    /**
        Initialize a signature from a packet
     */
    public init(packet:Packet) throws {
        guard packet.header.tag == .signature else {
            throw PacketableError.invalidPacketTag(packet.header.tag)
        }

        let data = packet.body
        
        guard data.count >= 6 else {
            throw DataError.tooShort(data.count)
        }
        
        let bytes = data.bytes
        
        guard Int(bytes[0]) == supportedVersion else {
            throw Signature.ParsingError.unsupportedVersion(bytes[0])
        }
        
        kind                = try Signature.Kind(type: bytes[1])
        chainID             = bytes[2]
//        publicKeyAlgorithm  = try PublicKeyAlgorithm(type: bytes[2])
        hashAlgorithm       = try Signature.HashAlgorithm(type: bytes[3])
        
        
        // hashed subpackets
        let hashedDataLength = Int(UInt32(bigEndianBytes: [UInt8](bytes[4 ... 5])))
        
        var ptr = 6
        guard bytes.count >= ptr + hashedDataLength else {
            throw DataError.tooShort(bytes.count)
        }
        
        hashedSubpacketables = try [SignatureSubpacket](data: Data(bytes[ptr ..< (ptr + hashedDataLength)])).toSignatureSubpacketables()
        
        ptr += hashedDataLength

        // unhashed subpackets
        guard bytes.count >= ptr + 2 else {
            throw DataError.tooShort(bytes.count)
        }
        
        let unhashedDataLength = Int(UInt32(bigEndianBytes: [UInt8](bytes[ptr ... ptr + 1])))
        ptr += 2
        
        guard bytes.count >= ptr + unhashedDataLength else {
            throw DataError.tooShort(bytes.count)
        }
        
        unhashedSubpacketables = try [SignatureSubpacket](data: Data(bytes[ptr ..< (ptr + unhashedDataLength)])).toSignatureSubpacketables()
        ptr += unhashedDataLength
        
        
        // left 16 bits of signed hash
         guard bytes.count >= ptr + 2 else {
            throw DataError.tooShort(bytes.count)
         }
        
        // ignoring
        leftTwoHashBytes = [UInt8](bytes[ptr ... (ptr + 1)])
        
        ptr += 2 // jump two-octets for left 16 bits of sig (ignoring signature length)

        guard bytes.count > ptr else {
            throw DataError.tooShort(bytes.count)
        }

        // signature
        signature = Data(bytes[ptr ..< bytes.count])
        ptr += signature.count
        
        guard bytes.count == ptr else {
            throw Signature.ParsingError.signatureHasExtraBytes(bytes.count - ptr)
        }

    }
    
    // MARK: Signing Helpers
    public init(bare kind: Signature.Kind, chainID: Int = 1, hashAlgorithm:Signature.HashAlgorithm = .sha256, hashedSubpacketables:[SignatureSubpacketable] = []) {
        self.kind = kind
        self.chainID = UInt8(chainID)
        self.hashAlgorithm = hashAlgorithm
        self.hashedSubpacketables = hashedSubpacketables
        self.unhashedSubpacketables = []
        self.leftTwoHashBytes = []
        self.signature = Data()
    }
    
    /**
        Serialize the signature data that is part of the data to hash and sign
        https://tools.ietf.org/html/rfc4880#section-5.2.4
     */
    public func signedData() throws -> Data {
        var data = Data()
        
        data.append(contentsOf: [UInt8(supportedVersion)])
        data.append(contentsOf: [kind.rawValue])
        data.append(chainID)
//        data.append(contentsOf: [publicKeyAlgorithm.rawValue])
        data.append(contentsOf: [hashAlgorithm.rawValue])
        
        // hashed subpackets
        let hashedSubpackets = try hashedSubpacketables.map({ try $0.toSubpacket() })
        let hashedSubpacketLength = hashedSubpackets.reduce(0, { $0 + $1.length })
        guard hashedSubpacketLength <= Int(UInt16.max) else {
            throw Signature.SerializingError.tooManySubpackets
        }
        // length
        data.append(contentsOf: UInt32(hashedSubpacketLength).twoByteBigEndianBytes())
        // data
        hashedSubpackets.forEach {
            data.append($0.toData())
        }
        
        return data
    }
    
    /**
        Serialize the signedData with the trailer that is to be hashed
        https://tools.ietf.org/html/rfc4880#section-5.2.4
     */
    public func dataToHash() throws -> Data {
        var dataToHash = Data()
        
        // append signature data
        let signatureData = try self.signedData()
        dataToHash.append(signatureData)
        
        // trailer
        dataToHash.append(self.trailer(for: signatureData))
        
        return dataToHash
    }

    /**
        Signature trailer
        https://tools.ietf.org/html/rfc4880#section-5.2.4
     */
    public func trailer(for signatureData:Data) -> Data {
        // trailer
        var data = Data()
        data.append(contentsOf: [UInt8(supportedVersion)])
        data.append(contentsOf: [0xFF])
        data.append(contentsOf: UInt32(signatureData.count).fourByteBigEndianBytes())
        
        return data
    }
    
    /**
        Set the signature data and left two hash bytes
     */
    mutating public func set(hash:Data, signature:Data) throws {
        guard hash.count >= 2 else {
            throw Signature.SerializingError.invalidHashLength(hash.count)
        }
        self.leftTwoHashBytes = [UInt8](hash.bytes[0...1])
        self.signature = signature
    }

    /**
        Serialize signature to packet body
     */
    public func toData() throws -> Data {
        var data = try signedData()
        
        // un-hashed subpackets
        let unhashedSubpackets = try unhashedSubpacketables.map({ try $0.toSubpacket() })
        let unhashedSubpacketLength = unhashedSubpackets.reduce(0, { $0 + $1.length })
        guard unhashedSubpacketLength <= Int(UInt16.max) else {
            throw Signature.SerializingError.tooManySubpackets
        }
        // length
        data.append(contentsOf: UInt32(unhashedSubpacketLength).twoByteBigEndianBytes())
        // data
        unhashedSubpackets.forEach {
            data.append($0.toData())
        }
        
        // left 16 bits
        data.append(contentsOf: leftTwoHashBytes)
        
        // signature
//        data.append(signature.numBits.twoByteBigEndianBytes()) // Length of signature UInt32
        data.append(signature)
        
//        for point in signature {
//            let signatureMPInt = MPInt(integerData: point)
//
//            data.append(contentsOf: signatureMPInt.lengthBytes)
//            data.append(signatureMPInt.data)
//        }
        
        return data
    }

}


