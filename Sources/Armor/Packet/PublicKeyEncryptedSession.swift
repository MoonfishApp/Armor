//
//  PublicKeyEncryptedSession.swift
//  
//
//  Created by Ronald Mannak on 8/5/22.
//

import Foundation
import MEWwalletTweetNacl

// Packet type 1: Session key encrypted with a public key
public struct PublicKeyEncryptedSession {
    public let tag: PacketTag = .publicKeyEncrypted
    public let version = 3
    public let keyID: Data
    public let algorithm: PublicKeyAlgorithm
    public let encryptedSessionKey: Data
    
    
    /// <#Description#>
    /// - Parameters:
    ///   - sessionKey: Symmetric key used to encrypt the message
    ///   - publicKey: curve25519 public key of recipient
    ///   - algorithm: Should always be ed25519 in Moonfish
    public init(encryptedSessionKey: Data, publicKey: PublicKey, algorithm: PublicKeyAlgorithm = .ed25519) throws {
        self.algorithm = algorithm
        
        // Create eight octet KeyID
        self.keyID = try publicKey.keyID() // eight octets
        assert(self.keyID.count == 8)
        self.encryptedSessionKey = encryptedSessionKey
    }

    /*
     let receiverKeys = try TweetNacl.keyPair(fromSecretKey: privateKey)
     let ephemKeys = try TweetNacl.keyPair()
     let message = "My name is Satoshi Buterin".data(using: .utf8)!
     let nonceData = Data(base64Encoded: self.nonce)!
     
     XCTAssertEqual(String(data: receiverKeys.publicKey.base64EncodedData(), encoding: .utf8), "C5YMNdqE4kLgxQhJO1MfuQcHP5hjVSXzamzd/TxlR0U=")
     XCTAssertEqual(String(data: nonceData.base64EncodedData(), encoding: .utf8), "1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej")
       
     // encrypt
     let secretbox = try TweetNacl.box(message: message, recipientPublicKey: receiverKeys.publicKey, senderSecretKey: ephemKeys.secretKey, nonce: nonceData)
     let secretboxString = String(data: secretbox.box.base64EncodedData(), encoding: .utf8)!
     let expectedCiphertext = "f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy"
     XCTAssertEqual(secretboxString.count, expectedCiphertext.count)
     
     // decrypt
     let decrypted = try TweetNacl.open(message: secretbox.box, nonce: nonceData, publicKey: ephemKeys.publicKey, secretKey: receiverKeys.secretKey)
     */
//    public func keyIDMatch(keyID: Data) -> Bool {
//        return false
//    }
}

extension PublicKeyEncryptedSession: Packetable {    
    
    public init(packet: Packet) throws {
        guard packet.header.tag == .publicKeyEncrypted else { throw PacketableError.invalidPacketTag(packet.header.tag) }
        let bytes = packet.body.bytes
        guard bytes.count > 11 else { throw PacketError.dataError } // bytes = 10 bytes
        guard Int(bytes[0]) == version else { throw Signature.ParsingError.unsupportedVersion(bytes[0]) }
        self.keyID = Data(bytes[1 ..< 9]) // See OnePassSignature
        guard let algorithm = PublicKeyAlgorithm(rawValue: bytes[9]), algorithm == .ed25519 else {
            throw PacketError.unsupportedAlgorithm(bytes[9])
        }
        self.algorithm = algorithm
        self.encryptedSessionKey = Data(bytes.suffix(from: 10))
    }
    
    public func toData() throws -> Data {
        // one octet version number
        var data = Data([UInt8(version)])
        // eight octet keyID
        data.append(self.keyID)
        // one octet public-key algorithm
        data.append(Data([algorithm.rawValue]))
        // Encrypted session key
        data.append(encryptedSessionKey)
        return data
    }
    
    
}

/*
 let recipientKeyPair = try TweetNacl.keyPair(fromSecretKey: recipientEthKey.data())
 guard let recipientPublicKeyString = String(data: recipientKeyPair.publicKey.base64EncodedData(), encoding: .utf8) else {
     fail("returned nil")
     return
 }
 
 let encryptedData = try EthEncryptedData.encrypt(plaintext: "My name is Satoshi Buterin", senderPrivateKey: self.senderPrivateKey, recipientPublicKey: recipientPublicKeyString)
 expect(Data(base64Encoded: encryptedData.ephemPublicKey)!.count) == 32
 
 
 // Decrypt using recipient's private key string
 let decryptedByRecipient = try encryptedData.decrypt(privateKey: recipientEthKey)
 expect(decryptedByRecipient) == "My name is Satoshi Buterin"

 // Decrypt using recipient's private key
 let decryptedByRecipientString = try encryptedData.decrypt(privateKey: self.recipientPrivateKeyString)
 expect(decryptedByRecipientString) == "My name is Satoshi Buterin"

 // Decrypt using sender's private key
 let decryptedBySender = try encryptedData.decrypt(senderPrivateKey: self.senderPrivateKey, recipientPublicKey: recipientPublicKeyString)
 expect(decryptedBySender) == "My name is Satoshi Buterin"
 */
