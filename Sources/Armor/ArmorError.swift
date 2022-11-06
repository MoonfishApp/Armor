//
//  File.swift
//  
//
//  Created by Ronald Mannak on 11/5/22.
//

import Foundation

public enum ArmorError: Error {
    case invalidMessage
    case invalidPacketTag(PacketTag)
    case invalidArmor
}
