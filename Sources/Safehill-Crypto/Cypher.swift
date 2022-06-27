//
//  Cypher.swift
//  
//
//  Created by Gennaro Frazzingaro on 9/1/21.
//

import Foundation
import CryptoKit

// TODO: Edit this. Should this be common across all clients, or unique per user?
let iv: [UInt8] = [0x00, 0x01, 0x02, 0x03,
                   0x04, 0x05, 0x06, 0x07,
                   0x08, 0x09, 0x0A, 0x0B
]
let protocolSalt = Data(bytes: iv, count: iv.count)


public struct SHCypher {
    
    enum DecryptionError: Error {
        case authenticationError
    }
    
    static func encrypt(_ data: Data, using key: SymmetricKey) throws -> Data {
        return try AES.GCM.seal(data, using: key).combined!
    }

    static func encrypt(
        _ messageToSeal: Data,
        to theirEncryptionKey: P256.KeyAgreement.PublicKey,
        using ephemeralKey: P256.KeyAgreement.PrivateKey,
        signedBy ourSigningKey: P256.Signing.PrivateKey) throws -> SHShareablePayload
    {
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: theirEncryptionKey)
        
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: protocolSalt,
            sharedInfo: ephemeralKey.publicKey.rawRepresentation + theirEncryptionKey.rawRepresentation + ourSigningKey.publicKey.rawRepresentation,
            outputByteCount: 32
        )
        
        let cypher = try SHCypher.encrypt(messageToSeal, using: symmetricKey)
        let signature = try ourSigningKey.signature(for: cypher +
                                                       ephemeralKey.publicKey.rawRepresentation +
                                                       theirEncryptionKey.rawRepresentation)
        
        return SHShareablePayload(ephemeralPublicKeyData: ephemeralKey.publicKey.rawRepresentation,
                                  cyphertext: cypher,
                                  signature: signature.rawRepresentation)
    }


    static func decrypt(data: Data, using key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    public static func decrypt(
        _ sealedMessage: SHShareablePayload,
        using ourKeyEncryptionKeyData: Data,
        from theirSigningKeyData: Data) throws -> Data
    {
        let encryptionKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: ourKeyEncryptionKeyData)
        let signingKey = try P256.Signing.PublicKey(rawRepresentation: theirSigningKeyData)
        return try SHCypher.decrypt(sealedMessage, using: encryptionKey, from: signingKey)
    }
    
    internal static func decrypt(
        _ sealedMessage: SHShareablePayload,
        using ourKeyEncryptionKey: P256.KeyAgreement.PrivateKey,
        from theirSigningKey: P256.Signing.PublicKey) throws -> Data
    {
        let data = sealedMessage.cyphertext + sealedMessage.ephemeralPublicKeyData + ourKeyEncryptionKey.publicKey.rawRepresentation
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: sealedMessage.signature)
        guard theirSigningKey.isValidSignature(signature, for: data) else {
            throw DecryptionError.authenticationError
        }
        
        let ephemeralKey = try P256.KeyAgreement.PublicKey(rawRepresentation: sealedMessage.ephemeralPublicKeyData)
        let sharedSecret = try ourKeyEncryptionKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
        
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: protocolSalt,
            sharedInfo: ephemeralKey.rawRepresentation +
                ourKeyEncryptionKey.publicKey.rawRepresentation +
                theirSigningKey.rawRepresentation,
            outputByteCount: 32
        )
        
        let sealedBox = try! AES.GCM.SealedBox(combined: sealedMessage.cyphertext)
        
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }
}
