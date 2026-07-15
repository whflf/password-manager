package dev.whflf.vault.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AesEncryptorTest {

    private AesEncryptor encryptor;
    private byte[] key;

    @BeforeEach
    void setUp() {
        encryptor = new AesEncryptor();
        key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
    }

    @Test
    void encrypt_thenDecrypt_returnsOriginal() {
        String original = "my-secret-password";

        AesEncryptor.EncryptionResult result = encryptor.encrypt(original, key);
        String decrypted = encryptor.decrypt(result.encryptedPassword(), result.iv(), key);

        assertEquals(original, decrypted);
    }

    @Test
    void encrypt_producesDifferentIvEachTime() {
        String plaintext = "same-password";

        AesEncryptor.EncryptionResult first = encryptor.encrypt(plaintext, key);
        AesEncryptor.EncryptionResult second = encryptor.encrypt(plaintext, key);

        assertNotEquals(first.iv(), second.iv());
    }

    @Test
    void encrypt_sameInputProducesDifferentCiphertext() {
        String plaintext = "same-password";

        AesEncryptor.EncryptionResult first = encryptor.encrypt(plaintext, key);
        AesEncryptor.EncryptionResult second = encryptor.encrypt(plaintext, key);

        assertNotEquals(first.encryptedPassword(), second.encryptedPassword());
    }

    @Test
    void decrypt_withWrongKey_throwsException() {
        AesEncryptor.EncryptionResult result = encryptor.encrypt("secret", key);

        byte[] wrongKey = new byte[32];
        new java.security.SecureRandom().nextBytes(wrongKey);

        assertThrows(IllegalStateException.class,
                () -> encryptor.decrypt(result.encryptedPassword(), result.iv(), wrongKey));
    }
}