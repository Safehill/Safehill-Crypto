//
//  User.swift
//  
//
//  Created by Gennaro Frazzingaro on 9/22/21.
//

import Foundation
import CryptoKit


protocol _SHCryptoUser {
    var publicKey: P256.KeyAgreement.PublicKey { get }
    var signature: P256.Signing.PublicKey { get }
}

public protocol SHCryptoUser {
    var publicKeyData: Data { get }
    var publicSignatureData: Data { get }
}


/// An entity known for its public key and signature
public struct SHRemoteCryptoUser : _SHCryptoUser, SHCryptoUser {
    public let publicKeyData: Data
    public let publicSignatureData: Data
    
    var publicKey: P256.KeyAgreement.PublicKey {
        try! P256.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)
    }
    var signature: P256.Signing.PublicKey {
        try! P256.Signing.PublicKey(rawRepresentation: publicKeyData)
    }
    
    public init(publicKeyData: Data, publicSignatureData: Data) throws {
        self.publicKeyData = publicKeyData
        self.publicSignatureData = publicSignatureData
    }
}


/// An entity whose private keys and signature are known.
/// Usually represents a user on the local device, as the private portion of the keys are never shared
public struct SHLocalCryptoUser : _SHCryptoUser, SHCryptoUser {
    
    fileprivate let privateSignature: P256.Signing.PrivateKey
    fileprivate let privateKey: P256.KeyAgreement.PrivateKey
    
    var publicKey: P256.KeyAgreement.PublicKey {
        self.privateKey.publicKey
    }
    
    var signature: P256.Signing.PublicKey {
        self.privateSignature.publicKey
    }
    
    public var publicKeyData: Data {
        self.privateKey.publicKey.rawRepresentation
    }
    public var publicSignatureData: Data {
        self.signature.rawRepresentation
    }
    
    static func generateKey() -> P256.KeyAgreement.PrivateKey {
        return P256.KeyAgreement.PrivateKey()
    }
    
    static func generateSignature() -> P256.Signing.PrivateKey {
        return P256.Signing.PrivateKey()
    }
    
    /// Generates a new set of keys for encryption and signing
    public init() {
        self.privateKey = SHLocalCryptoUser.generateKey()
        self.privateSignature = SHLocalCryptoUser.generateSignature()
    }
    
    init(key: P256.KeyAgreement.PrivateKey, signature: P256.Signing.PrivateKey) {
        self.privateKey = key
        self.privateSignature = signature
    }
    
    public init(usingKeychainEntryWithLabel label: String) throws {
        let privateKey = try SHKeychain.retrieveKey(label: label + ".key") as P256.KeyAgreement.PrivateKey?
        let privateSignature = try SHKeychain.retrieveKey(label: label + ".signature") as P256.Signing.PrivateKey?
        
        guard let pk = privateKey, let sig = privateSignature  else {
            if privateKey == nil {
                throw SHKeychain.Error.generic("No entry in keychain for \(label).key")
            } else if privateSignature == nil {
                throw SHKeychain.Error.generic("No entry in keychain for \(label).signature")
            } else {
                throw SHKeychain.Error.generic("No entry in keychain with label \(label)(.key|.signature)")
            }
        }
        
        self.init(key: pk, signature: sig)
    }
    
    public func saveToKeychain(withLabel label: String) throws {
        try SHKeychain.storeKey(privateKey, label: label + ".key")
        try SHKeychain.storeKey(privateSignature, label: label + ".signature")
    }
}


public struct SHUserContext {
    let myUser: SHLocalCryptoUser
    
    public init(user: SHLocalCryptoUser) {
        self.myUser = user
    }
}


extension SHUserContext {
    public func shareable(data: Data, with user: SHCryptoUser) throws -> SHShareablePayload {
        let ephemeralKey = P256.KeyAgreement.PrivateKey()
        let userPublicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: user.publicKeyData)
        let encrypted = try SHCypher.encrypt(data,
                                             to: userPublicKey,
                                             using: ephemeralKey,
                                             signedBy: myUser.privateSignature)
        return SHShareablePayload(ephemeralPublicKeyData: ephemeralKey.publicKey.rawRepresentation,
                                  cyphertext: encrypted.cyphertext,
                                  signature: encrypted.signature,
                                  recipient: user)
    }
    
    public func decrypt(_ data: Data,
                        usingEncryptedSecret encryptedSecret: SHShareablePayload,
                        receivedFrom sender: SHCryptoUser) throws -> Data {
        let senderPublicSignature = try P256.Signing.PublicKey(rawRepresentation: sender.publicSignatureData)
        let secretData = try SHCypher.decrypt(encryptedSecret,
                                              using: myUser.privateKey,
                                              from: senderPublicSignature)
        let secret = try SymmetricKey(rawRepresentation: secretData)
        return try SHCypher.decrypt(data: data, using: secret)
    }
}
