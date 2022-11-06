//
//  AsciiArmor.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/**
    ASCII Armor block constants
*/
public enum ArmorMessageBlock:String {
    case publicKey = "PUBLIC KEY BLOCK"
    case signature = "SIGNATURE"
    case message = "MESSAGE"

    public var begin:String {
        return "\(ArmorMessageBlock.begin)\(self.rawValue)\(ArmorMessageBlock.dashes)"
    }
    
    public var end:String {
        return "\(ArmorMessageBlock.end)\(self.rawValue)\(ArmorMessageBlock.dashes)"
    }
    
    static let dashes   = "-----"
    static let begin    = "-----BEGIN PGP "
    static let end      = "-----END PGP "
    
    static let headerVersionKey = "Version"
    static let headerCommentKey = "Comment"
    static let headerCharsetKey = "Charset"
    
    public init?(line:String) {
        let strippedHeader = line.replacingOccurrences(of: ArmorMessageBlock.begin, with: "").replacingOccurrences(of: ArmorMessageBlock.end, with: "").replacingOccurrences(of: ArmorMessageBlock.dashes, with: "")
        
        self.init(rawValue: strippedHeader)
    }    
}

/**
    ASCII Armor Parsing Errors
*/
public enum AsciiArmorError:Error {
    case noValidHeader
    case blockLineMismatch
    case missingChecksum
    case invalidChecksum
    case invalidArmor
}

/**
    An ASCII Armored PGP Message.
    For example:
 
     -----BEGIN PGP PUBLIC KEY BLOCK-----
     Comment: <String>
     Data <String:Base64 Encoded Bytes>
     "=" + CRC24(Data) <String: Base64 encoded CRC-24 checksum>
     -----END PGP PUBLIC KEY BLOCK-----
 
    https://tools.ietf.org/html/rfc4880#section-6.2
 */
public struct AsciiArmorMessage {
    
    public static let version = "0.1"
    
    public let packetData:Data
    public let crcChecksum:Data
    public let blockType:ArmorMessageBlock
    public var headers = [
        ArmorMessageBlock.headerVersionKey: "Pretty Good Crypto / \(version)",
        ArmorMessageBlock.headerCommentKey: "https://www.moonfish.app",
        ArmorMessageBlock.headerCharsetKey: "UTF-8"
    ]
    
    
    public init(packetData:Data, blockType:ArmorMessageBlock) {
        self.packetData = packetData
        self.crcChecksum = packetData.crc24Checksum
        self.blockType = blockType
    }
    
    /**
        Convert a PGP Message to an ASCII Armored PGP Message block
     */
    public init(message:Message, blockType:ArmorMessageBlock) {
        self.init(packetData: message.data(), blockType: blockType)
    }

    /**
        Parse an ASCII Armor string
    */
    public init(string:String) throws {
        
        let scanner = Scanner(string: string)
        scanner.charactersToBeSkipped = nil
        _ = scanner.scanUpToString("-----BEGIN PGP")
        guard scanner.isAtEnd == false else { throw AsciiArmorError.noValidHeader }

        let lines = String(scanner.string[scanner.currentIndex...]).components(separatedBy: CharacterSet.newlines).filter { !$0.isEmpty }
        guard   lines.count > 0,
                let headerBlockType = ArmorMessageBlock(line: lines[0].trimmingCharacters(in: CharacterSet.whitespaces))
        else {
            throw AsciiArmorError.noValidHeader
        }
        
        guard lines.count > 3 else {
            throw AsciiArmorError.invalidArmor
        }
        
        var packetStart = 1
        // quick and dirty header parsing until empty line
        headers = [String: String]()
        while lines[packetStart].trimmingCharacters(in: CharacterSet.whitespacesAndNewlines).count > 0 {
            let scanner = Scanner(string: lines[packetStart])
            scanner.charactersToBeSkipped = nil
            guard let key = scanner.scanUpToString(":")?.trimmingCharacters(in: .whitespacesAndNewlines), scanner.isAtEnd == false, packetStart < lines.count else {
                break
            }
            let value = String(scanner.string[scanner.currentIndex...]).dropFirst().trimmingCharacters(in: .whitespacesAndNewlines)
            headers.updateValue(value, forKey: key)
            packetStart = packetStart + 1
        }
        
        // crc
        self.crcChecksum = try lines[lines.count - 2].replacingOccurrences(of: "=", with: "").fromBase64()

        // footer
        let footerBlockType = ArmorMessageBlock(line: lines[lines.count - 1].trimmingCharacters(in: CharacterSet.whitespaces))
        
        guard headerBlockType == footerBlockType else {
            throw AsciiArmorError.blockLineMismatch
        }
        
        self.blockType = headerBlockType
        
        let packets = try lines[packetStart ..< (lines.count - 2)].joined(separator: "").fromBase64()
        
        guard self.crcChecksum == packets.crc24Checksum else {
            throw AsciiArmorError.invalidChecksum
        }
        
        self.packetData = packets
    }
    
    /**
        Returns the ascii armored representation
    */
    public func toString() -> String {
        let packetDataB64 = packetData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        
        var armoredMessage = ""
        
        armoredMessage += "\(blockType.begin)\n"
        
//        if let comment = self.comment {
//            armoredMessage += "\(ArmorMessageBlock.commentPrefix) \(comment)\n"
//        }
        for (key, value) in headers {
            armoredMessage += "\(key): \(value)\n"
        }
        
        armoredMessage += "\n"
        armoredMessage += "\(packetDataB64)\n"
        armoredMessage += "=\(crcChecksum.toBase64())\n"
        armoredMessage += "\(blockType.end)"

        return armoredMessage
    }
}

public extension AsciiArmorMessage {
    
    /// Convenience initializer for creating and extracting mail signatures
    /// - Parameters:
    ///   - hashValue: hash of the document
    ///   - signature: signature
    ///   - chainID: chain ID (default is 1, Ethereum)
    init(hashValue: Data, signature: Data, publicKey: String?, chainID: Int = 1) throws {
        
        // Signature packet
        var sigPacket = MFSignaturePacket(bare: .textDocument, chainID: chainID, hashAlgorithm: .sha256, hashedSubpacketables: [])
        try sigPacket.set(hash: hashValue, signature: signature)
        let encodedPacket = try sigPacket.toPacket()
        var packetData = encodedPacket.toData()
                
        // Public key packet
        if let publicKey = publicKey, let publicKeyData = Data(base64Encoded: publicKey) {
            // Add 0x40 prefix to key in accordance with OpenPGP standard
            let publicKeyDataPacket = try ECPublicKey(curve: .ed25519, prefixedRawData: Data([0x40]) + publicKeyData)
            let keyPacket = try PublicKey(create: .ed25519, publicKeyData: publicKeyDataPacket).toPacket()
            packetData = packetData + keyPacket.toData()
        }
        
        self.init(packetData: packetData, blockType: .signature)
    }
 
    /// Decodes signature from
    /// - Returns: Signature and optional public key
    func decodeSignature() throws -> (signature: Data, chainID: Int, publicKey: String?) {
        let packets = try [Packet](data: self.packetData)
        guard let firstPacket = packets.first else { throw ArmorError.invalidArmor }
        let packet = try MFSignaturePacket(packet:firstPacket)
        
        // Decode public key packet if available
        var publicKey: String? = nil
        if packets.count > 1 {
            if let publicKeyPacket = try? PublicKey(packet: packets[1]), let publicKeyData = publicKeyPacket.publicKeyData as? ECPublicKey {
                publicKey = String(data: publicKeyData.rawData.base64EncodedData(), encoding: .utf8)
            }
        }
        return (signature: packet.signature, chainID: Int(packet.chainID), publicKey: publicKey)
    }
}
