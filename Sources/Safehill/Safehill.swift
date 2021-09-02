import Foundation
import CryptoKit

public struct SHUser {
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
    init() {
        self.privateKey = SHUser.generateKey()
        self.privateSignature = SHUser.generateSignature()
    }
    
    init(key: P256.KeyAgreement.PrivateKey, signature: P256.Signing.PrivateKey) {
        self.privateKey = key
        self.privateSignature = signature
    }
    
    init(usingKeychainEntryWithLabel label: String) throws {
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
    
    func saveToKeychain(withLabel label: String) throws {
        try SHKeychain.storeKey(privateKey, label: label + ".key")
        try SHKeychain.storeKey(privateSignature, label: label + ".signature")
    }
}

public struct SHShareablePayload {
    let ephemeralPublicKeyData: Data
    let cyphertext: Data
    let signature: Data
    let recipient: SHUser?
    
    init(ephemeralPublicKeyData: Data,
         cyphertext: Data,
         signature: Data,
         recipient: SHUser? = nil) {
        self.ephemeralPublicKeyData = ephemeralPublicKeyData
        self.cyphertext = cyphertext
        self.signature = signature
        self.recipient = recipient
    }
    
    func toTuple() -> ((ephemeralPublicKeyData: Data, cyphertext: Data, signature: Data)) {
        return (self.ephemeralPublicKeyData, self.cyphertext, self.signature)
    }
}

public struct SHEncryptedData {
    fileprivate let privateSecret: SymmetricKey
    public let encryptedData: Data
    
    init(privateSecret: SymmetricKey, data: Data) {
        self.privateSecret = privateSecret
        self.encryptedData = data
    }
    
    init(clearData: Data) throws {
        let secret = SymmetricKey(size: .bits256)
        self.init(privateSecret: secret,
                  data: try SHCypher.encrypt(clearData, using: secret))
    }
}

public struct SHContext {
    let myUser: SHUser
    
    func share(secret: SHEncryptedData, with user: SHUser) throws -> SHShareablePayload {
        let encrypted = try SHCypher.encrypt(secret.privateSecret.rawRepresentation,
                                             to: user.publicKey,
                                             signedBy: myUser.privateSignature)
        return SHShareablePayload(ephemeralPublicKeyData: encrypted.ephemeralPublicKeyData,
                                  cyphertext: encrypted.cyphertext,
                                  signature: encrypted.signature,
                                  recipient: user)
    }
    
    func decrypt(_ data: Data,
                 usingEncryptedSecret encryptedSecret: SHShareablePayload,
                 receivedFrom sender: SHUser) throws -> Data {
        let secretData = try SHCypher.decrypt(encryptedSecret.toTuple(),
                                              using: myUser.privateKey,
                                              from: sender.signature)
        let secret = try SymmetricKey(rawRepresentation: secretData)
        return try SHCypher.decrypt(data: data, using: secret)
    }
}
