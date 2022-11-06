//
//  File.swift
//  
//
//  Created by Ronald Mannak on 5/5/22.
//

import Foundation

/**
    Represents a signed binary document
    Packets: a signature packet
 */
public struct MFSignedBinaryDocument: Messagable { // Signable, 
    
    public var binaryData: Data
    public var signature: MFSignaturePacket
    
    public init(binary:Data, publicKeyAlgorithm:PublicKeyAlgorithm, chainID: Int, hashedSubpacketables:[SignatureSubpacketable]) {
        
        binaryData = binary
        signature = MFSignaturePacket(bare: Signature.Kind.binaryDocument, chainID: chainID, hashAlgorithm: .sha256, hashedSubpacketables: hashedSubpacketables)
    }
    
    public func signableData() throws -> Data {
        return binaryData
    }
    
    public func toPackets() throws -> [Packet] {
        return try [self.signature.toPacket()]
    }
}
