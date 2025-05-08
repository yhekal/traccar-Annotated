/*
 * Copyright 2022 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.api.signature;

import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Singleton
// &begin[CryptoManager]
public class CryptoManager {

    private final Storage storage;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    @Inject
    public CryptoManager(Storage storage) {
        this.storage = storage;
    }
    // &begin[sign]
    public byte[] sign(byte[] data) throws GeneralSecurityException, StorageException {
        if (privateKey == null) {
            initializeKeys();
        }
        Signature signature = Signature.getInstance("SHA256withECDSA"); // &line[Signature_getInstance_L]
        signature.initSign(privateKey); // &line[Signature_initSign_L]
        signature.update(data); // &line[Signature_update_L]
        byte[] block = signature.sign(); // &line[Signature_sign_L]
        byte[] combined = new byte[1 + block.length + data.length];
        combined[0] = (byte) block.length;
        System.arraycopy(block, 0, combined, 1, block.length);
        System.arraycopy(data, 0, combined, 1 + block.length, data.length);
        return combined;
    }
    // &end[sign]
    // &begin[verify]
    public byte[] verify(byte[] data) throws GeneralSecurityException, StorageException {
        if (publicKey == null) {
            initializeKeys();
        }
        Signature signature = Signature.getInstance("SHA256withECDSA"); // &line[Signature_getInstance_L]
        signature.initVerify(publicKey); // &line[Signature_initVerify_L]
        int length = data[0];
        byte[] originalData = new byte[data.length - 1 - length];
        System.arraycopy(data, 1 + length, originalData, 0, originalData.length);
        signature.update(originalData); // &line[Signature_update_L]
        if (!signature.verify(data, 1, length)) { // &line[Signature_verify_L]
            throw new SecurityException("Invalid signature");
        }
        return originalData;
    }
    // &end[verify]

// &begin[initializeKeys]
    private void initializeKeys() throws StorageException, GeneralSecurityException {
        KeystoreModel model = storage.getObject(KeystoreModel.class, new Request(new Columns.All()));
        if (model != null) {
            publicKey = KeyFactory.getInstance("EC") // &line[KeyGeneration_getInstance_L]
                    .generatePublic(new X509EncodedKeySpec(model.getPublicKey())); // &line[KeyGeneration_X509EncodedKeySpec_L, KeyGeneration_generatePublic_L]
            privateKey = KeyFactory.getInstance("EC") // &line[KeyGeneration_getInstance_L]
                    .generatePrivate(new PKCS8EncodedKeySpec(model.getPrivateKey())); // &line[KeyGeneration_PKCS8EncodedKeySpec_L, KeyGeneration_generatePrivate_L]
        } else {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC"); // &line[KeyPairGenerator_getInstance]
            generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom()); // &line[KeyGeneration_initialize_L, KeyGeneration_ECGenParameterSpec_L, SourceOfRandomness_SecureRandom_L]
            KeyPair pair = generator.generateKeyPair(); // &line[KeyGeneration_generateKeyPair_L]


            publicKey = pair.getPublic(); // &line[KeyGeneration_getPublic_L]
            privateKey = pair.getPrivate(); // &line[KeyGeneration_getPrivate_L]

            model = new KeystoreModel();
            model.setPublicKey(publicKey.getEncoded()); // &line[setPublicKey, KeyGeneration_getEncoded_L]
            model.setPrivateKey(privateKey.getEncoded()); // &line[setPrivateKey, KeyGeneration_getEncoded_L]
            storage.addObject(model, new Request(new Columns.Exclude("id")));
        }
    }
// &end[initializeKeys]
}
// &end[CryptoManager]
