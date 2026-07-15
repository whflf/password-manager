package dev.whflf.vault.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CryptoIntegrationTest {

    private Pbkdf2Util pbkdf2Util;
    private AesEncryptor aesEncryptor;

    @BeforeEach
    void setUp() {
        pbkdf2Util = new Pbkdf2Util();
        aesEncryptor = new AesEncryptor();
    }

    @Test
    void fullFlow_registerAndDecryptVaultEntry() {
        String masterPassword = "master-secret-123";
        String salt = pbkdf2Util.generateSalt();
        String verifier = pbkdf2Util.deriveVerifier(masterPassword, salt);

        assertTrue(pbkdf2Util.verify(masterPassword, salt, verifier));

        byte[] encKey = pbkdf2Util.deriveEncryptionKey(masterPassword, salt);
        String sitePassword = "my-site-password";
        AesEncryptor.EncryptionResult encrypted = aesEncryptor.encrypt(sitePassword, encKey);
        String decrypted = aesEncryptor.decrypt(encrypted.encryptedPassword(), encrypted.iv(), encKey);

        assertEquals(sitePassword, decrypted);
    }

    @Test
    void fullFlow_wrongMasterPassword_cannotDecrypt() {
        String masterPassword = "correct-master";
        String salt = pbkdf2Util.generateSalt();

        byte[] correctKey = pbkdf2Util.deriveEncryptionKey(masterPassword, salt);
        AesEncryptor.EncryptionResult encrypted = aesEncryptor.encrypt("site-password", correctKey);

        byte[] wrongKey = pbkdf2Util.deriveEncryptionKey("wrong-master", salt);
        assertThrows(IllegalStateException.class,
                () -> aesEncryptor.decrypt(encrypted.encryptedPassword(), encrypted.iv(), wrongKey));
    }

    @Test
    void fullFlow_keyIsConsistentAcrossSessions() {
        String masterPassword = "stable-master";
        String salt = pbkdf2Util.generateSalt();
        String sitePassword = "google-password";

        byte[] firstSessionKey = pbkdf2Util.deriveEncryptionKey(masterPassword, salt);
        AesEncryptor.EncryptionResult encrypted = aesEncryptor.encrypt(sitePassword, firstSessionKey);

        byte[] secondSessionKey = pbkdf2Util.deriveEncryptionKey(masterPassword, salt);
        String decrypted = aesEncryptor.decrypt(encrypted.encryptedPassword(), encrypted.iv(), secondSessionKey);

        assertEquals(sitePassword, decrypted);
    }

    @Test
    void fullFlow_twoUsersWithSamePassword_getIsolatedVaults() {
        String sharedPassword = "common-master";
        String saltUser1 = pbkdf2Util.generateSalt();
        String saltUser2 = pbkdf2Util.generateSalt();

        byte[] keyUser1 = pbkdf2Util.deriveEncryptionKey(sharedPassword, saltUser1);
        byte[] keyUser2 = pbkdf2Util.deriveEncryptionKey(sharedPassword, saltUser2);

        String secret = "shared-site-password";
        AesEncryptor.EncryptionResult encryptedByUser1 = aesEncryptor.encrypt(secret, keyUser1);

        assertThrows(IllegalStateException.class,
                () -> aesEncryptor.decrypt(encryptedByUser1.encryptedPassword(), encryptedByUser1.iv(), keyUser2));
    }
}
