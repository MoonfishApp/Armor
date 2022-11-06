//  Converted to Swift 5.5 by Swiftify v5.5.24279 - https://swiftify.com/
//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
/*
import Foundation

public enum ArmorType : Int {
    case message = 1
    case publicKey = 2
    case secretKey = 3
    case multipartMessagePartXOfY = 4
    case multipartMessagePartX = 5
    case signature = 6
    case cleartextSignedMessage = 7 // TODO: -----BEGIN PGP SIGNED MESSAGE-----
}

/// ASCII Armor message.
public class Armor: NSObject {
    
    /// Scans message for PGP armor and discards the message before the armor
    /// - Parameter message: message that includes armor
    /// - Returns: the armored message as Data
    public static func read(message: String) throws -> Data {
        let scanner = Scanner(string: message)
        scanner.charactersToBeSkipped = nil
        
        let _ = scanner.scanUpToString("-----BEGIN PGP")
        guard scanner.isAtEnd == false else {
            throw WalletError.noArmorFound
        }
        let armor = String(scanner.string[scanner.currentIndex...])
        return try Armor.readArmored(armor)
    }
    
    /// Whether the data is PGP ASCII armored message.
    public class func isArmoredData(_ data: Data) -> Bool {

        // detect if armored, check for string -----BEGIN PGP
        let str = String(data: data, encoding: .utf8)
        let scanner = Scanner(string: str ?? "")
        scanner.charactersToBeSkipped = nil
        let _ = scanner.scanUpToString("-----BEGIN PGP")
        return scanner.isAtEnd == false
    }

    /// Convert binary PGP message to ASCII armored format.
    public class func armored(_ data: Data, as type: ArmorType) -> String {
        return self.armored(data, as: type, part: Int.max, of: Int.max)
    }

    public class func armored(_ data: Data, as type: ArmorType, part: Int, of ofParts: Int) -> String {
        let headers = [
            "Version": "Pretty Good Crypto / 0.1",
            "Comment": "https://www.moonfish.app",
            "Charset": "UTF-8"
        ]

        var headerString = "-----"
        var footerString = "-----"
        switch type {
        case .publicKey:
            headerString += "BEGIN PGP PUBLIC KEY BLOCK"
            footerString += "END PGP PUBLIC KEY BLOCK"
        case .secretKey:
            headerString += "BEGIN PGP PRIVATE KEY BLOCK"
            footerString += "END PGP PRIVATE KEY BLOCK"
        case .signature:
            headerString += "BEGIN PGP SIGNATURE"
            footerString += "END PGP SIGNATURE"
        case .message:
            headerString += "BEGIN PGP MESSAGE"
            footerString += "END PGP MESSAGE"
        case .multipartMessagePartX:
            headerString += "BEGIN PGP MESSAGE, PART \(NSNumber(value: part))"
            footerString += "END PGP MESSAGE, PART \(NSNumber(value: part))"
        case .multipartMessagePartXOfY:
            headerString += "BEGIN PGP MESSAGE, PART \(NSNumber(value: part))/\(NSNumber(value: ofParts))"
            footerString += "END PGP MESSAGE, PART \(NSNumber(value: part))/\(NSNumber(value: ofParts))"
        default:
            assert(true, "Message type not supported")
        }

        headerString += "-----\n"
        footerString += "-----\n"

        var armoredMessage = ""
        // - An Armor Header Line, appropriate for the type of data
        armoredMessage += headerString

        // - Armor Headers
        for key in headers.keys {
            armoredMessage += "\(key): \(headers[key] ?? "")\n"
        }

        // - A blank (zero-length, or containing only whitespace) line
        armoredMessage += "\n"

        // - The ASCII-Armored data
        let radix64 = data.base64EncodedString(options: [.lineLength76Characters, .endLineWithLineFeed])
        armoredMessage += radix64
        armoredMessage += "\n"

        // - An Armor Checksum
        let checksum = data.crc24Checksum //pgp_CRC24()
        var c = [UInt8](repeating: 0, count: 3) // 24 bit
        c[0] = UInt8(checksum >> 16)
        c[1] = UInt8(checksum >> 8)
        c[2] = UInt8(checksum)

        let checksumData = Data(c) //Data(bytes: &c, length: MemoryLayout.size(ofValue: c))
        armoredMessage += "="
        armoredMessage += checksumData.base64EncodedString(options: [.lineLength76Characters, .endLineWithLineFeed])
        armoredMessage += "\n"

        // - The Armor Tail, which depends on the Armor Header Line
        armoredMessage += footerString
        return armoredMessage
    }

    /// Read Checksum and strip it from the input Base64 string
    public class func readChecksum(_ base64String: String) -> (String, String?) {
        // 1. Find checksum at the last non-empty line
        var checksumString: String? = nil

        let lines = base64String.components(separatedBy: CharacterSet.newlines)
        // 2. Find checksum line
        var output = ""
        for line in lines.reversed() {
            if line.hasPrefix("=") {
                checksumString = String(line.dropFirst())
            } else if line.count > 0 {
                // 3. re-build base64 string without checksum line
                output.insert(contentsOf: "\(line)\n", at: output.startIndex)
            }
        }
        return (output, checksumString)
    }

    /// Convert ASCII armored PGP message to binary format.
    public class func readArmored(_ string: String) throws -> Data {

        let scanner = Scanner(string: string)
        scanner.charactersToBeSkipped = nil

        let newlineSet = CharacterSet.newlines
        let notNewlineSet = CharacterSet.newlines.inverted

        // check header line
        let headerLine = scanner.scanUpToCharacters(from: CharacterSet.newlines)
        let validHeaders = ["-----BEGIN PGP MESSAGE-----", "-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----BEGIN PGP SECRET KEY BLOCK-----", "-----BEGIN PGP SIGNATURE-----"]
        guard let headerLine = headerLine, (validHeaders.contains(headerLine) || headerLine.hasPrefix("-----BEGIN PGP MESSAGE, PART")) else {
            throw WalletError.invalidMessage
        }

        // consume newline
        _ = scanner.scanUpToString("\r")
        _ = scanner.scanUpToString("\n")

        if scanner.scanCharacters(from: newlineSet) == nil {
            // Scan headers (Optional)
            _ = scanner.scanUpToCharacters(from: notNewlineSet)
            while let _ = scanner.scanCharacters(from: notNewlineSet) {
                // consume newline
                _ = scanner.scanString("\r")
                _ = scanner.scanString("\n")
            }
        }

        // skip blank line
        _ = scanner.scanCharacters(from: newlineSet)
        // consume till footer        
        guard let line = scanner.scanUpToString("-----")?.replacingOccurrences(of: "\r\n", with: "\n") else {
            throw WalletError.noBase64StringFound
        }
        let (base64StringResult, checksumString) = self.readChecksum(line)
        guard let checksumString = checksumString else {
            throw WalletError.noChecksum
        }
        let base64String = base64StringResult.replacingOccurrences(of: "\n", with: "")

        // read footer
        let footer = scanner.scanUpToCharacters(from: newlineSet)
        // consume newline
        _ = scanner.scanString("\r")
        _ = scanner.scanString("\n")

        guard footer == "-----END \(headerLine.dropFirst(11))" else {
            throw WalletError.invalidPGPHeaders
        }

        // binary data from base64 part
        guard let binaryData = Data(base64Encoded: base64String) else {
            throw WalletError.noBinaryData
        }

        // The checksum with its leading equal sign MAY appear on the first line after the base64 encoded data.
        // validate checksum
        let readChecksumData = Data(base64Encoded: checksumString)

        var calculatedCRC24 = binaryData.pgp_CRC24()
        calculatedCRC24 = CFSwapInt32HostToBig(calculatedCRC24)
        calculatedCRC24 = calculatedCRC24 >> 8
        let calculatedCRC24Data = Data(bytes: &calculatedCRC24, count: 3) //withUnsafeBytes(of: calculatedCRC24) { Data($0) } //Data(bytes: UnsafeRawPointer(&calculatedCRC24), length: 3)
        guard calculatedCRC24Data == readChecksumData else {
            throw WalletError.checksumMismatch
        }

        return binaryData
    }
/*
    /// Helper function to convert input data (ASCII or binary) to array of PGP messages.
    class func convertArmoredMessage2BinaryBlocks(whenNecessary binOrArmorData: Data) throws -> [Data]? {
        let binRingData = binOrArmorData
        // detect if armored, check for string -----BEGIN PGP
        if PGPArmor.isArmoredData(binRingData) {
            let armoredString = String(data: binRingData, encoding: .utf8)
            if let subRange = Range<String.Index>(NSRange(location: 0, length: armoredString?.count ?? 0), in: armoredString) { armoredString = armoredString?.replacingOccurrences(of: "\r\n", with: "\n", options: [], range: subRange) }
            if let subRange = Range<String.Index>(NSRange(location: 0, length: armoredString?.count ?? 0), in: armoredString) { armoredString = armoredString?.replacingOccurrences(of: "\n", with: "\r\n", options: [], range: subRange) }

            let extractedBlocks: [String] = []
            let regex = try NSRegularExpression(pattern: "-----(BEGIN|END) (PGP)[A-Z ]*-----", options: .dotMatchesLineSeparators)
            var offset = 0
            regex?.enumerateMatches(in: armoredString ?? "", options: .reportCompletion, range: NSRange(location: 0, length: armoredString?.count ?? 0), using: { result, ,  in
                autoreleasepool {
                    var substring: String? = nil
                    if let range = result?.range {
                        substring = (armoredString as NSString?)?.substring(with: range)
                    }
                    if substring?.contains("END") ?? false {
                        let endIndex = (result?.range.location ?? 0) + (result?.range.length ?? 0)
                        extractedBlocks.append((armoredString as NSString?)?.substring(with: NSRange(location: offset, length: endIndex - offset)) ?? "")
                    } else if substring?.contains("BEGIN") ?? false {
                        offset = result?.range.location ?? 0
                    }
                }
            })

            let extractedData: [Data] = []
            for extractedString in extractedBlocks {
                autoreleasepool {
                    var armorError: Error? = nil
                    let armoredData = try PGPArmor.readArmored(extractedString)
                    if armoredData == nil || armorError != nil {
                        if error != nil {
                            if let armorError = armorError {
                                error = armorError
                            }
                        }
                        return nil
                    }

                    extractedData.pgp_addObject(armoredData)
                }
            }
            return extractedData
        }
        return [binRingData]
    } */
}
*/
