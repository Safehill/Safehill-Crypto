import Foundation
import CryptoKit

public protocol SHUser {
    var publicKey: P256.KeyAgreement.PublicKey { get }
    var signature: P256.Signing.PublicKey { get }
}

/// An entity known for its public key and signature
public struct SHRemoteUser : SHUser {
    public let publicKey: P256.KeyAgreement.PublicKey
    public let signature: P256.Signing.PublicKey
    
    public init(publicKeyData: Data, publicSignatureData: Data) throws {
        self.publicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)
        self.signature = try P256.Signing.PublicKey(rawRepresentation: publicSignatureData)
        
    }
}

/// An entity whose private keys and signature are known.
/// Usually represents a user on the local device, as the private portion of the keys are never shared
public struct SHLocalUser : SHUser {
    fileprivate let privateSignature: P256.Signing.PrivateKey
    fileprivate let privateKey: P256.KeyAgreement.PrivateKey
    
    public var publicKey: P256.KeyAgreement.PublicKey {
        self.privateKey.publicKey
    }
    
    public var signature: P256.Signing.PublicKey {
        self.privateSignature.publicKey
    }
    
    static func generateKey() -> P256.KeyAgreement.PrivateKey {
        return P256.KeyAgreement.PrivateKey()
    }
    
    static func generateSignature() -> P256.Signing.PrivateKey {
        return P256.Signing.PrivateKey()
    }
    
    /// Generates a new set of keys for encryption and signing
    public init() {
        self.privateKey = SHLocalUser.generateKey()
        self.privateSignature = SHLocalUser.generateSignature()
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

public struct SHContext {
    let myUser: SHLocalUser
    
    public init(user: SHLocalUser) {
        self.myUser = user
    }
    
    public func shareable(data: Data, with user: SHUser) throws -> SHShareablePayload {
        let ephemeralKey = P256.KeyAgreement.PrivateKey()
        let encrypted = try SHCypher.encrypt(data,
                                             to: user.publicKey,
                                             using: ephemeralKey,
                                             signedBy: myUser.privateSignature)
        return SHShareablePayload(ephemeralPublicKeyData: ephemeralKey.publicKey.rawRepresentation,
                                  cyphertext: encrypted.cyphertext,
                                  signature: encrypted.signature,
                                  recipient: user)
    }
    
    public func decrypt(_ data: Data,
                        usingEncryptedSecret encryptedSecret: SHShareablePayload,
                        receivedFrom sender: SHUser) throws -> Data {
        let secretData = try SHCypher.decrypt(encryptedSecret,
                                              using: myUser.privateKey,
                                              from: sender.signature)
        let secret = try SymmetricKey(rawRepresentation: secretData)
        return try SHCypher.decrypt(data: data, using: secret)
    }
}
