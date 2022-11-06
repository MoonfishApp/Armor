//
//  ModificationDetection.swift
//  
//
//  Created by Ronald Mannak on 8/5/22.
//

import Foundation
import CryptoKit

// Packet type 19: Modification Detection Code Packet
public struct ModificationDetection {
    public let tag: PacketTag = .modificationDetection
    public let digest: Data
    
    public init(content: Data) throws {
        self.digest = Data(CryptoKit.Insecure.SHA1.hash(data: content).compactMap{ UInt8($0) })
        assert(digest.count == 20)
    }
    
    public func verify(_ data: Data) throws -> Bool {
        return self.digest == Data(CryptoKit.Insecure.SHA1.hash(data: data).compactMap{ UInt8($0) })
    }
}

extension ModificationDetection: Packetable {
    
    public init(packet: Packet) throws {
        guard packet.header.tag == .modificationDetection else { throw ArmorError.invalidPacketTag(packet.header.tag) }
        guard packet.body.count == 20 else { throw ArmorError.invalidMessage }
        digest = packet.body
    }
    
    public func toData() throws -> Data {
        return digest
    }
    
    
}
