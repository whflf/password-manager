package dev.whflf.vault.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class Pbkdf2UtilTest {

    private Pbkdf2Util pbkdf2Util;

    @BeforeEach
    void setUp() {
        pbkdf2Util = new Pbkdf2Util();
    }

    @Test
    void generateSalt_producesUniqueValues() {
        String salt1 = pbkdf2Util.generateSalt();
        String salt2 = pbkdf2Util.generateSalt();
        assertNotEquals(salt1, salt2);
    }

    @Test
    void verify_withCorrectPassword_returnsTrue() {
        String salt = pbkdf2Util.generateSalt();
        String verifier = pbkdf2Util.deriveVerifier("master123", salt);

        assertTrue(pbkdf2Util.verify("master123", salt, verifier));
    }

    @Test
    void verify_withWrongPassword_returnsFalse() {
        String salt = pbkdf2Util.generateSalt();
        String verifier = pbkdf2Util.deriveVerifier("master123", salt);

        assertFalse(pbkdf2Util.verify("wrong-password", salt, verifier));
    }

    @Test
    void deriveEncryptionKey_sameInputProducesSameKey() {
        String salt = pbkdf2Util.generateSalt();

        byte[] key1 = pbkdf2Util.deriveEncryptionKey("master123", salt);
        byte[] key2 = pbkdf2Util.deriveEncryptionKey("master123", salt);

        assertArrayEquals(key1, key2);
    }

    @Test
    void deriveEncryptionKey_differentSaltProducesDifferentKey() {
        byte[] key1 = pbkdf2Util.deriveEncryptionKey("master123", pbkdf2Util.generateSalt());
        byte[] key2 = pbkdf2Util.deriveEncryptionKey("master123", pbkdf2Util.generateSalt());

        assertFalse(java.util.Arrays.equals(key1, key2));
    }
}
