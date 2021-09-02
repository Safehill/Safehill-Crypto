//
//  Signing.swift
//  
//
//  Created by Gennaro Frazzingaro on 9/1/21.
//

import Foundation
import CryptoKit

func digest(for data: Data) -> SHA512Digest {
    return SHA512.hash(data: data)
}

//func temporarySignature(for transactionData: Data,
//                        durationInSeconds: TimeInterval = 10) throws -> P256.Signing.ECDSASignature {
//    if !SecureEnclave.isAvailable {
//        // Handle devices without secure enclave
//        let privateKey = P256.Signing.PrivateKey()
//        try SHKeychain.storeKey(privateKey, label: keyTag)
//    }
//    else {
//        // Request for biometric authentication
//        let accessControl = SecAccessControlCreateWithFlags(nil,
//                                                            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
//                                                            [.privateKeyUsage, .userPresence],
//                                                            nil)!
//        // Keep user authenticated for 30s
//        let authContext = LAContext()
//        authContext.touchIDAuthenticationAllowableReuseDuration = durationInSeconds
//        authContext.localizedReason = "Authorizing <operation>"
//        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl,
//                                                                   authenticationContext: authContext)
//        try SHKeychain.storeKey(privateKey, account: keyTag)
//
//        let publicKey = privateKey.publicKey.compactRepresentation!
//        let digest512 = SHA512.hash(data: transactionData)
//        return try! privateKey.signature(for: Data(digest512))
//
//    }
//
//    let publicKey = privateKey.publicKey.compactRepresentation!
//
//    let signature = try privateKey.signature(for: transactionData)
//    return signature
//}
//
//func validateSignature(for data: Data, signature: P256.Signing.ECDSASignature) -> Bool {
//    let publicKey = try! Curve25519.Signing.PublicKey(
//      rawRepresentation: albusSigningPublicKeyData)
//    if publicKey.isValidSignature(signatureForData, for: data) {
//      print("Dumbledore sent this data.")
//    }
//    if publicKey.isValidSignature(signatureForDigest,
//      for: Data(digest512)) {
//      print("Data received == data sent.")
//    }
//}
