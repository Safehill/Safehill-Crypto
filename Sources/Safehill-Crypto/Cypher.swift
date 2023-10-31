//
//  Cypher.swift
//  
//
//  Created by Gennaro Frazzingaro on 9/1/21.
//

import Foundation
#if os(Linux)
@_exported import Crypto
#else
import CryptoKit
#endif


public struct SHCypher {
    
    public enum DecryptionError: Error {
        case authenticationError
    }
    
    public static func generateRandomBytes(length: Int = 32) -> Data? {
#if os(Linux)
        SymmetricKey.init(size: .init(bitCount: length)).rawRepresentation
        /// Not sure why the struct `SecureBytes` is not public in Crypto
        /// `SymmetricKey` will do the trick for now (but is it less cryptographically secure?)
        /// https://security.stackexchange.com/questions/270500/symmetrickey-vs-secrandomcopybytes
//        try! SecureBytes(count: length)
#else
        var bytes = Data(count: length)
        let result = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!)
        }
        if result == errSecSuccess {
            return bytes
        } else {
            return nil
        }
#endif
    }
    
    public static func generateOTPCode(secret: Data, digits: Int = 6, expiresIn period: TimeInterval = TimeInterval(30)) -> String {
        let symmetricKey = SymmetricKey(data: secret)
        var counter = UInt64(Date().timeIntervalSince1970 / period).bigEndian

        let counterData = withUnsafeBytes(of: &counter) { Array($0) }
        let hash = HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: symmetricKey)
     
        var truncatedHash = hash.withUnsafeBytes { ptr -> UInt32 in
            let offset = ptr[hash.byteCount - 1] & 0x0f
     
            let truncatedHashPtr = ptr.baseAddress! + Int(offset)
            return truncatedHashPtr.bindMemory(to: UInt32.self, capacity: 1).pointee
        }
     
        truncatedHash = UInt32(bigEndian: truncatedHash)
        truncatedHash = truncatedHash & 0x7FFF_FFFF
        truncatedHash = truncatedHash % UInt32(pow(10, Float(digits)))
     
        return String(format: "%0*u", digits, truncatedHash)
    }
    
    static func encrypt(_ data: Data, using key: SymmetricKey, nonce: AES.GCM.Nonce? = nil) throws -> Data {
        return try AES.GCM.seal(data, using: key, nonce: nonce).combined!
    }

    static func encrypt(
        _ messageToSeal: Data,
        receiverPublicKey: P256.KeyAgreement.PublicKey,
        ephemeralKey: P256.KeyAgreement.PrivateKey,
        protocolSalt: Data,
        signedBy senderSignatureKey: P256.Signing.PrivateKey) throws -> SHShareablePayload
    {
        let sharedSecretFromKeyAgreement = try ephemeralKey.sharedSecretFromKeyAgreement(with: receiverPublicKey)
        
        let sharedInfo = ephemeralKey.publicKey.derRepresentation + receiverPublicKey.derRepresentation + senderSignatureKey.publicKey.derRepresentation
        let symmetricKey = sharedSecretFromKeyAgreement.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: protocolSalt,
            sharedInfo: sharedInfo,
            outputByteCount: 32
        )
        
        let cypher = try SHCypher.encrypt(messageToSeal, using: symmetricKey)
        let messageToSign = cypher + ephemeralKey.publicKey.derRepresentation + receiverPublicKey.derRepresentation
        let signature = try senderSignatureKey.signature(for: messageToSign)
        
        return SHShareablePayload(ephemeralPublicKeyData: ephemeralKey.publicKey.derRepresentation,
                                  cyphertext: cypher,
                                  signature: signature.derRepresentation)
    }


    static func decrypt(data: Data, using key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    public static func decrypt(
        _ sealedMessage: SHShareablePayload,
        encryptionKeyData ourKeyEncryptionKeyData: Data,
        protocolSalt: Data,
        from theirSigningKeyData: Data) throws -> Data
    {
        let encryptionKey = try P256.KeyAgreement.PrivateKey(derRepresentation: ourKeyEncryptionKeyData)
        let signingKey = try P256.Signing.PublicKey(derRepresentation: theirSigningKeyData)
        return try SHCypher.decrypt(sealedMessage, encryptionKey: encryptionKey, protocolSalt: protocolSalt, signedBy: signingKey)
    }
    
    internal static func decrypt(
        _ sealedMessage: SHShareablePayload,
        encryptionKey ourKeyEncryptionKey: P256.KeyAgreement.PrivateKey,
        protocolSalt: Data,
        signedBy theirSigningKey: P256.Signing.PublicKey) throws -> Data
    {
        let data = sealedMessage.cyphertext + sealedMessage.ephemeralPublicKeyData + ourKeyEncryptionKey.publicKey.derRepresentation
        let signature = try P256.Signing.ECDSASignature(derRepresentation: sealedMessage.signature)
        guard theirSigningKey.isValidSignature(signature, for: data) else {
            throw DecryptionError.authenticationError
        }
        
        let ephemeralKey = try P256.KeyAgreement.PublicKey(derRepresentation: sealedMessage.ephemeralPublicKeyData)
        let sharedSecret = try ourKeyEncryptionKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
        
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: protocolSalt,
            sharedInfo: ephemeralKey.derRepresentation +
                ourKeyEncryptionKey.publicKey.derRepresentation +
                theirSigningKey.derRepresentation,
            outputByteCount: 32
        )
        
        return try self.decrypt(data: sealedMessage.cyphertext, using: symmetricKey)
    }
}
