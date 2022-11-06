//
//  ContactID.swift
//  
//
//  Created by Ronald Mannak on 8/15/22.
//

import Foundation

/**
    A UserID packet customized for Contact
    https://tools.ietf.org/html/rfc4880#section-5.11
 */
public struct ContactID: Packetable {
    
    public var tag:PacketTag {
        return .userID
    }

    public let contact: Contact
    public var content: Data
    
    public init(packet:Packet) throws {
        guard packet.header.tag == .userID else {
            throw PacketableError.invalidPacketTag(packet.header.tag)
        }
        
        try self.init(content: packet.body)
    }
    
    public init(contact: Contact) throws {
        self.contact = contact
        self.content = try JSONEncoder().encode(contact)
    }
    
    public init(content: Data) throws {
        self.content = content
        let decoder = JSONDecoder()
        self.contact = try decoder.decode(Contact.self, from: content)
    }
    
    public func toData() -> Data {
        return content
    }
}

