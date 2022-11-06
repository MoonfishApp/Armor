//
//  EncryptedIntegrity.swift
//  
//
//  Created by Ronald Mannak on 8/5/22.
//

import Foundation
import CryptoKit

// Packet type 18: Symmetrically encrypted and integrity protected data packet
public struct EncryptedIntegrity {
    
    public let version = 1
    public let tag: PacketTag = .integrityProtectedData
    
    public let sealedBox: Data
    public let key: Data?
    
    public init(plaintext: String, key: SymmetricKey = SymmetricKey(size: .bits256)) throws {
        guard let data = plaintext.data(using: .utf8) else {
            throw PacketError.dataError
        }
        let literal = LiteralData(contents: data)
        let mod = try ModificationDetection(content: literal.toData())
        try self.init(literal: literal, modification: mod, key: key)
    }
    
    public init(literal: LiteralData, modification: ModificationDetection, key: SymmetricKey = SymmetricKey(size: .bits256)) throws {
        var clearData = try literal.toPacket().toData()
        try clearData.append(modification.toPacket().toData())
        let box = try AES.GCM.seal(clearData, using: key)
        guard let combined = box.combined else { throw PacketError.dataError }
        self.sealedBox = combined
        self.key = key.withUnsafeBytes({ Data(Array($0)) })
    }
    
    public func decrypt(keyData: Data) throws -> Data {
        let key = SymmetricKey(data: keyData)
        let sealedBox = try AES.GCM.SealedBox(combined: self.sealedBox)
        let clearData = try AES.GCM.open(sealedBox, using: key)
        let packets = try [Packet](data: clearData)
        guard packets.count == 2 else {
            throw PacketError.dataError
        }
        let literal = try LiteralData(packet: packets[0])
        let mod = try ModificationDetection(packet: packets[1])
        // check hash
        guard try mod.verify(literal.toData()) == true else {
            throw PacketError.contentHasBeenAltered
        }
        return literal.contents
    }
}

extension EncryptedIntegrity: Packetable {
    
    public init(packet: Packet) throws {
        guard packet.header.tag == .integrityProtectedData else { throw PacketableError.invalidPacketTag(packet.header.tag) }
        let bytes = packet.body.bytes

        // Check length and version
        guard bytes.count > 1 else { throw PacketError.dataError }
        guard Int(bytes[0]) == version else { throw Signature.ParsingError.unsupportedVersion(bytes[0]) }
        
        self.sealedBox = Data(bytes.suffix(from: 1))
        self.key = nil
    }
    
    public func toData() throws -> Data {
        var data = Data([UInt8(version)])
        data.append(sealedBox)
        return data
    }
}
