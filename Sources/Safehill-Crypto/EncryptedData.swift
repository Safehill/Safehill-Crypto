//
//  EncryptedData.swift
//  
//
//  Created by Gennaro Frazzingaro on 9/22/21.
//

import Foundation
import CryptoKit

public struct SHEncryptedData {
    /// privateSecret should never be shared
    public let privateSecret: SymmetricKey
    public let encryptedData: Data
    
    public init(privateSecret: SymmetricKey, data: Data) {
        self.privateSecret = privateSecret
        self.encryptedData = data
    }
    
    public init(clearData: Data) throws {
        let secret = SymmetricKey(size: .bits256)
        self.init(privateSecret: secret,
                  data: try SHCypher.encrypt(clearData, using: secret))
    }
}

