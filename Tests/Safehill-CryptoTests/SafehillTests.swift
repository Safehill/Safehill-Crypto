import XCTest
@testable import Safehill_Crypto
import CryptoKit

final class SafehillTests: XCTestCase {
    
    func testEncryptDecryptSharedSecret() throws {
        let originalString = "This is a test"
        let clear = originalString.data(using: .utf8)!
        
        let key = SymmetricKey(size: .bits256)
        let cypher = try SHCypher.encrypt(clear, using: key)
        
        let decrypted = try SHCypher.decrypt(data: cypher, using: key)
        let decryptedString = String(data: decrypted, encoding: .utf8)
        
        XCTAssertEqual(originalString, decryptedString)
    }
    
    func testEncryptDecryptWithPublicKeySignature() throws {
        let originalString = "This is a test"
        let d1 = originalString.data(using: .utf8)!
        // Alice's keys and signature
        let ephemeralSecret = P256.KeyAgreement.PrivateKey()
        let Asignature = P256.Signing.PrivateKey()
        // Bob's keys
        let PB = P256.KeyAgreement.PrivateKey()
        
        /* Alice sends encrypted d1 to Bob */
        let Pd1 = SymmetricKey(size: .bits256)
        let Ed1 = try SHCypher.encrypt(d1, using: Pd1)
        let EBPd1 = try SHCypher.encrypt(Pd1.rawRepresentation,
                                         to: PB.publicKey,
                                         using: ephemeralSecret,
                                         signedBy: Asignature)
        
        /*
         Alice uploads Ed1 and EBPd1 to the server. Bob retrieves both and …
         Bob gets to d1 using his private key
         */
        let decryptedPd1 = try SHCypher.decrypt(EBPd1, using: PB, from: Asignature.publicKey)
        let decryptedPd1Key = try SymmetricKey(rawRepresentation: decryptedPd1)
        let decryptedd1 = try SHCypher.decrypt(data: Ed1, using: decryptedPd1Key)
        let decryptedString = String(data: decryptedd1, encoding: .utf8)
        
        XCTAssertEqual(originalString, decryptedString)
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
        
        let encryptedSecret = try aliceContext.shareable(data: encryptedData.privateSecret.rawRepresentation, with: bob)
        // upload encrypted secret
        
        /** Once Bob gets encryptedData, encryptedSecret  */
        let decryptedData = try bobContext.decrypt(encryptedData.encryptedData,
                                                   usingEncryptedSecret: encryptedSecret,
                                                   receivedFrom: alice)
        let decryptedString = String(data: decryptedData, encoding: .utf8)
        
        XCTAssertEqual(originalString, decryptedString)
        
        /** Ensure another user in possession of Alice's signature and public key can NOT decrypt that content */
        let hacker = SHLocalCryptoUser()
        let hackerContext = SHUserContext(user: hacker)
        
        do {
            let _ = try hackerContext.decrypt(encryptedData.encryptedData,
                                              usingEncryptedSecret: encryptedSecret,
                                              receivedFrom: alice)
            XCTFail()
        } catch SHCypher.DecryptionError.authenticationError {
            print("Authentication failed for hacker")
        }
        
        /** Ensure that if Alice's private key is compromised, the message for Bob still can't get decrypted (because Bob's private key is still safe) */
        do {
            let _ = try aliceContext.decrypt(encryptedData.encryptedData,
                                                       usingEncryptedSecret: encryptedSecret,
                                                       receivedFrom: alice)
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
        let encryptedSecret = try aliceContext.shareable(data: encryptedData.privateSecret.rawRepresentation, with: alice)
        // upload encrypted secret
        
        /** Once Bob gets encryptedData, encryptedSecret  */
        let decryptedData = try aliceContext.decrypt(encryptedData.encryptedData,
                                                   usingEncryptedSecret: encryptedSecret,
                                                   receivedFrom: alice)
        let decryptedString = String(data: decryptedData, encoding: .utf8)
        
        XCTAssertEqual(originalString, decryptedString)
    }
    
    func _testKeychain() throws {
        let alice = SHLocalCryptoUser()
        try alice.saveToKeychain(withLabel: "alice")
        
        let alice2 = try SHLocalCryptoUser(usingKeychainEntryWithLabel: "alice")
        
        XCTAssertTrue(alice.publicKey.compactRepresentation == alice2.publicKey.compactRepresentation)
        XCTAssertTrue(alice.signature.compactRepresentation == alice2.signature.compactRepresentation)
    }
    
}
