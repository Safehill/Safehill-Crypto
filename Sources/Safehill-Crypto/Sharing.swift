//
//  Context.swift
//  
//
//  Created by Gennaro Frazzingaro on 9/22/21.
//

import Foundation
import CryptoKit


public struct SHShareablePayload {
    public let ephemeralPublicKeyData: Data
    public let cyphertext: Data
    public let signature: Data
    let recipient: SHUser?
    
    public init(ephemeralPublicKeyData: Data,
         cyphertext: Data,
         signature: Data,
         recipient: SHUser? = nil) {
        self.ephemeralPublicKeyData = ephemeralPublicKeyData
        self.cyphertext = cyphertext
        self.signature = signature
        self.recipient = recipient
    }
}
