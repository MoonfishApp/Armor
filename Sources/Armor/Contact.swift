//
//  File.swift
//
//
//  Created by Ronald Mannak on 8/8/22.
//

import Foundation

// Note: We only need to save name, email, public key and eth address
public struct Contact: Codable, Identifiable {
    public let id: UUID
    public let name: String?
    public let email: String
    public let ensName: String?
    public let udName: String?
    public let ethAddress: String
    public let publicKey: String?
    public let chainID: Int
    
    public init(name: String? = nil, email: String, ensName: String?, udName: String?, ethAddress: String, publicKey: String?, chainID: Int = 1) {
        self.id = UUID()
        self.name = name
        self.email = email
        self.ensName = ensName
        self.udName = udName
        self.ethAddress = ethAddress
        self.publicKey = publicKey
        self.chainID = chainID
    }
}

extension Contact: Equatable {
}

extension Contact {
    /*
    private static func url() throws -> URL {
        return try URL.sharedContainerURL(filename: "contacts.json")
    }
    
    public static func load() throws -> [Contact] {
        let url = try url()
        let contactsData = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode([Contact].self, from: contactsData)
    }
    
    public static func save(_ contacts: [Contact]) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(contacts)
        let url = try url()
        try data.write(to: url, options: .atomic)
    }
    
    public static func delete() throws {
        try FileManager.default.removeItem(at: url())
    } */
    
    public var keyID: Data? {
        guard let publicKey = publicKey,
                let publicKeyData = Data(base64Encoded: publicKey),
                let publicKeyDataPacket = try? ECPublicKey(curve: .ed25519, prefixedRawData: Data([0x40]) + publicKeyData) else {
            return nil
        }
        let keyPacket = PublicKey(create: .ed25519, publicKeyData: publicKeyDataPacket)
        return try? keyPacket.keyID()
    }
}
