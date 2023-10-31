import XCTest
@testable import Safehill_Crypto
import CryptoKit

final class SafehillCryptoTests: XCTestCase {
    
    let protocolSalt = SHCypher.generateRandomBytes()!
    
    func testUserIdentifier() throws {
        let kotlinGeneratedBase64SignatureData = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFp2uNurkYUh3U7O9m/wO+Oqcwnisxs97I7EmYuuGh3z4t72rNyI/WZcB+5DITlS4L0ydZhF8FAzv5FLMPmE5lw=="
        guard let signatureData = Data(base64Encoded: kotlinGeneratedBase64SignatureData) else {
            XCTAssert(false)
            return
        }
        let swiftIdentifier = SHHash.stringDigest(for: signatureData)
        
        let kotlinIdentifier = "dc292efc6bc0b4b4f53ca90bb30a6e741b45712f665f9cf32f01d3aca3e76e173ee4251aebb2df945a7179dcf45cbfcc1868ec8b8d35447e09533f85c2b520d3"

        XCTAssertEqual(swiftIdentifier, kotlinIdentifier)
    }
    
    func testEncryptDecryptSharedSecret() throws {
        let originalString = "This is our secret"
        let clear = originalString.data(using: .utf8)!
        
        let key = SymmetricKey(size: .bits256)
        let cypher = try SHCypher.encrypt(clear, using: key)
        
        /// Ensure 2 encryptions generate different results (randomness) and that base64 encoding is stable
        let cypher2 = try SHCypher.encrypt(clear, using: key)
        XCTAssertEqual(cypher.base64EncodedString(), cypher.base64EncodedString())
        XCTAssertNotEqual(cypher.base64EncodedString(), cypher2.base64EncodedString())
        XCTAssertEqual(cypher2.base64EncodedString(), cypher2.base64EncodedString())
        
        let decrypted = try SHCypher.decrypt(data: cypher, using: key)
        let decryptedString = String(data: decrypted, encoding: .utf8)
        
        XCTAssertEqual(originalString, decryptedString)
    }
    
    func testDecryptKotlinJavaSharedSecret() throws {
        let clear = "Text to encrypt"
        
        let cypherBase64="geaWMwzC9G39anYi5be9/LDtydKeRdbV9e5A/EoXPw=="
        let keyBase64="10/w7o2juYBrGMh32/KbveULW9jk2tejpyUAD+uC6PE="
        let ivBase64="sqKsYi3dhXDTyRsB"
        
        let cypher = Data(base64Encoded: cypherBase64)!
        let iv = Data(base64Encoded: ivBase64)!
        let key = try SymmetricKey(rawRepresentation: Data(base64Encoded: keyBase64)!)
        
        let nonce = try AES.GCM.Nonce(data: Data(base64Encoded: ivBase64)!)
        let iosCypher = try SHCypher.encrypt(clear.data(using: .utf8)!, using: key, nonce: nonce)
        let iosCypherBase64 = iosCypher.base64EncodedString()
        XCTAssertEqual(iosCypherBase64, "\(ivBase64)\(cypherBase64)")
        
        let decrypted = try SHCypher.decrypt(data: iv + cypher, using: key)
        let decryptedString = String(data: decrypted, encoding: .utf8)
        
        XCTAssertEqual(clear, decryptedString)
    }
    
    func testEncryptDecryptWithPublicKeySignature() throws {
        let string = "This is a test"
        let data = string.data(using: .utf8)!
        
        let senderSignatureKeys = P256.Signing.PrivateKey()
        let receiverEncryptionKeys = P256.KeyAgreement.PrivateKey()
        
        let ephemeralSecret = P256.KeyAgreement.PrivateKey()
        
        let secret = SymmetricKey(size: .bits256)
        let encryptedDataWithSecret = try SHCypher.encrypt(data, using: secret)
        let encryptedSecretWithReceiverPublicKey = try SHCypher.encrypt(
            secret.rawRepresentation,
            receiverPublicKey: receiverEncryptionKeys.publicKey,
            ephemeralKey: ephemeralSecret,
            protocolSalt: protocolSalt,
            signedBy: senderSignatureKeys
        )
        
        /*
         SENDER shares `encryptedDataWithSecret` and `encryptedSecretUsingReceiverPublicKey` with RECEIVER.
         RECEIVER decrypts `encryptedSecretUsingReceiverPublicKey` to retrieve `decryptedSecret`,
         which can be used to decrypt `encryptedDataWithSecret`.
         */
        let decryptedSecretData = try SHCypher.decrypt(
            encryptedSecretWithReceiverPublicKey,
            encryptionKey: receiverEncryptionKeys,
            protocolSalt: protocolSalt,
            signedBy: senderSignatureKeys.publicKey
        )
        let decryptedSecret = try SymmetricKey(rawRepresentation: decryptedSecretData)
        let decryptedData = try SHCypher.decrypt(data: encryptedDataWithSecret, using: decryptedSecret)
        let decryptedString = String(data: decryptedData, encoding: .utf8)
        
        XCTAssertEqual(string, decryptedString)
    }
    
    func testEncryptDecryptWithPublicKeySignatureJavaKotlinEquivalent() throws {
        let string = "This is a test"
        let data = string.data(using: .utf8)!
        
        let senderSignatureKeys = try P256.Signing.PrivateKey(derRepresentation: Data(base64Encoded: "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAOR3bJoS1nd5Gw0XSONtpIlz5mqJe4WT6LkGZf+w5oWg==")!)
        let receiverEncryptionKeys = try P256.KeyAgreement.PrivateKey(derRepresentation: Data(base64Encoded: "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDe32Jdsu36/b2y7ABNa4H91wVE6XAujaQ4D6mBDjUimg==")!)
        
        let ephemeralSecret = try P256.KeyAgreement.PrivateKey(derRepresentation: Data(base64Encoded: "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAM39KUQHguCdY26PBqXykOJhHARAaEYRS8i75Mck2aFw==")!)
        
        let secret = try SymmetricKey(rawRepresentation: Data(base64Encoded: "Qd91ZA8Ojpok04GChToIhJAJDxrf2X7jcCKNi/SURV8=")!)
        let encryptedSecret = try SHCypher.encrypt(data, using: secret, nonce: AES.GCM.Nonce(data: Data(base64Encoded: "Y8Lav7pxxBQisRfF")!))
        let encryptedDataWithReceiverPublicKey = try SHCypher.encrypt(
            secret.rawRepresentation,
            receiverPublicKey: receiverEncryptionKeys.publicKey,
            ephemeralKey: ephemeralSecret,
            protocolSalt: protocolSalt,
            signedBy: senderSignatureKeys
        )
        
        /*
         SENDER shares `encryptedDataWithSecret` and `encryptedSecretUsingReceiverPublicKey` with RECEIVER.
         RECEIVER decrypts `encryptedSecretUsingReceiverPublicKey` to retrieve `decryptedSecret`,
         which can be used to decrypt `encryptedDataWithSecret`.
         */
        let decryptedSecretData = try SHCypher.decrypt(
            encryptedDataWithReceiverPublicKey,
            encryptionKey: receiverEncryptionKeys,
            protocolSalt: protocolSalt,
            signedBy: senderSignatureKeys.publicKey
        )
        let decryptedSecret = try SymmetricKey(rawRepresentation: decryptedSecretData)
        let decryptedData = try SHCypher.decrypt(data: encryptedSecret, using: decryptedSecret)
        let decryptedString = String(data: decryptedData, encoding: .utf8)
        
        XCTAssertEqual(string, decryptedString)
    }

    func testShareablePayloadAliceAndBob() throws {
        let alice = SHLocalCryptoUser()
        let bob = SHLocalCryptoUser()
        let aliceContext = SHUserContext(user: alice)
        let bobContext = SHUserContext(user: bob)
        
        /** Alice uploads encrypted content for Bob (and only Bob) to decrypt*/
        let originalString = "This is a test"
        let stringAsData = originalString.data(using: .utf8)!
        let encryptedData = try SHEncryptedData(clearData: stringAsData)
        // upload encrypted data
        
        let encryptedSecret = try aliceContext.shareable(
            data: encryptedData.privateSecret.rawRepresentation,
            protocolSalt: protocolSalt,
            with: bob
        )
        // upload encrypted secret
        
        /** Once Bob gets encryptedData, encryptedSecret  */
        let decryptedData = try bobContext.decrypt(
            encryptedData.encryptedData,
            usingEncryptedSecret: encryptedSecret,
            protocolSalt: protocolSalt,
            receivedFrom: alice
        )
        let decryptedString = String(data: decryptedData, encoding: .utf8)
        
        XCTAssertEqual(originalString, decryptedString)
        
        /** Ensure another user in possession of Alice's signature and public key can NOT decrypt that content */
        let hacker = SHLocalCryptoUser()
        let hackerContext = SHUserContext(user: hacker)
        
        do {
            let _ = try hackerContext.decrypt(
                encryptedData.encryptedData,
                usingEncryptedSecret: encryptedSecret,
                protocolSalt: protocolSalt,
                receivedFrom: alice
            )
            XCTFail()
        } catch SHCypher.DecryptionError.authenticationError {
            print("Authentication failed for hacker")
        }
        
        /** Ensure that if Alice's private key is compromised, the message for Bob still can't get decrypted (because Bob's private key is still safe) */
        do {
            let _ = try aliceContext.decrypt(
                encryptedData.encryptedData,
                usingEncryptedSecret: encryptedSecret,
                protocolSalt: protocolSalt,
                receivedFrom: alice
            )
            XCTFail()
        } catch SHCypher.DecryptionError.authenticationError {
            print("Authentication failed for alice")
        }
    }
    
    func testShareablePayloadAliceToSelf() throws {
        let alice = SHLocalCryptoUser()
        
        let originalString = "This is a test"
        let stringAsData = originalString.data(using: .utf8)!
        let encryptedData = try SHEncryptedData(clearData: stringAsData)
        // upload encrypted data
        
        let aliceContext = SHUserContext(user: alice)
        let encryptedSecret = try aliceContext.shareable(
            data: encryptedData.privateSecret.rawRepresentation,
            protocolSalt: protocolSalt,
            with: alice
        )
        // upload encrypted secret
        
        /** Once Bob gets encryptedData, encryptedSecret  */
        let decryptedData = try aliceContext.decrypt(
            encryptedData.encryptedData,
            usingEncryptedSecret: encryptedSecret,
            protocolSalt: protocolSalt,
            receivedFrom: alice
        )
        let decryptedString = String(data: decryptedData, encoding: .utf8)
        
        XCTAssertEqual(originalString, decryptedString)
    }
    
    func _testKeychain() throws {
        let alice = SHLocalCryptoUser()
        try alice.saveKeysToKeychain(withLabel: "alice")
        
        let alice2 = try SHLocalCryptoUser(usingKeychainEntryWithLabel: "alice")
        
        XCTAssertTrue(alice.publicKey.compactRepresentation == alice2.publicKey.compactRepresentation)
        XCTAssertTrue(alice.signature.compactRepresentation == alice2.signature.compactRepresentation)
    }
    
    func testSigning() throws {
        let user = SHLocalCryptoUser()
        let data = "test data".data(using: .utf8)!
        let signatureForData = try user.signature(for: data)
        let digest512 = Data(SHA512.hash(data: data))
        let signatureForDigest = try user.signature(for: digest512)
        
        let publicSignature = try P256.Signing.PublicKey(derRepresentation: user.publicSignatureData)
        XCTAssert(publicSignature.isValidSignature(signatureForData, for: data))
        XCTAssert(publicSignature.isValidSignature(signatureForDigest, for: digest512))
    }
    
    func testGenerateOTP() {
        let secret = SymmetricKey(size: .bits128).rawRepresentation
        let code1 = SHCypher.generateOTPCode(secret: secret, digits: 6)
        XCTAssert(code1.count == 6)
        
        let code2 = SHCypher.generateOTPCode(secret: secret, digits: 6)
        XCTAssert(code1.count == 6)
        XCTAssert(code1 == code2)
        
        let timeInterval = TimeInterval(0.5)
        let code3 = SHCypher.generateOTPCode(secret: secret, digits: 6, expiresIn: timeInterval)
        let code4 = SHCypher.generateOTPCode(secret: secret, digits: 6, expiresIn: timeInterval)
        XCTAssert(code3 == code4)
        
        sleep(1)
        
        let code5 = SHCypher.generateOTPCode(secret: secret, digits: 6, expiresIn: timeInterval)
        XCTAssert(code4 != code5)
    }
}
