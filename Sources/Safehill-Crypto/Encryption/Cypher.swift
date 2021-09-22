//
//  Cypher.swift
//  
//
//  Created by Gennaro Frazzingaro on 9/1/21.
//

import Foundation
import CryptoKit

let protocolSalt = "TODO: Edit this. Should this be common across all clients?".data(using: .utf8)!


public struct SHCypher {
    
    enum DecryptionError: Error {
        case authenticationError
    }
    
    private static func deriveSymmetricKey(privateKey: P256.KeyAgreement.PrivateKey,
                                           publicKey: P256.KeyAgreement.PublicKey,
                                           signedBy ourSigningKey: P256.Signing.PrivateKey) throws -> SymmetricKey {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: protocolSalt,
            sharedInfo: privateKey.publicKey.rawRepresentation + publicKey.rawRepresentation + ourSigningKey.publicKey.rawRepresentation,
            outputByteCount: 32
        )
        
        return symmetricKey
    }
    
    static func encrypt(_ data: Data, using key: SymmetricKey) throws -> Data {
        return try AES.GCM.seal(data, using: key).combined!
    }

    static func encrypt(_ data: Data,
                        to theirEncryptionKey: P256.KeyAgreement.PublicKey,
                        using ephemeralKey: P256.KeyAgreement.PrivateKey,
                        signedBy ourSigningKey: P256.Signing.PrivateKey) throws -> SHShareablePayload {
        let symmetricKey = try SHCypher.deriveSymmetricKey(privateKey: ephemeralKey,
                                                           publicKey: theirEncryptionKey,
                                                           signedBy: ourSigningKey)
        let cypher = try SHCypher.encrypt(data, using: symmetricKey)
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
    
    public static func decrypt(data: Data, using keyData: Data) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        let key = try SymmetricKey(rawRepresentation: data)
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    static func decrypt(_ sealedMessage: SHShareablePayload,
                        using ourKeyEncryptionKey: P256.KeyAgreement.PrivateKey,
                        from theirSigningKey: P256.Signing.PublicKey) throws -> Data {
        let data = sealedMessage.cyphertext + sealedMessage.ephemeralPublicKeyData + ourKeyEncryptionKey.publicKey.rawRepresentation
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: sealedMessage.signature)
        guard theirSigningKey.isValidSignature(signature, for: data) else {
            throw DecryptionError.authenticationError
        }
        
        let ephemeralKey = try P256.KeyAgreement.PublicKey(rawRepresentation: sealedMessage.ephemeralPublicKeyData)
        let sharedSecret = try ourKeyEncryptionKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
        
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self,
                                                                salt: protocolSalt,
                                                                sharedInfo: ephemeralKey.rawRepresentation +
                                                                    ourKeyEncryptionKey.publicKey.rawRepresentation +
                                                                    theirSigningKey.rawRepresentation,
                                                                outputByteCount: 32)
        
        let sealedBox = try! AES.GCM.SealedBox(combined: sealedMessage.cyphertext)
        
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }
}
