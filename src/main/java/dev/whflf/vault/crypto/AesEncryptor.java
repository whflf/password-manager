package dev.whflf.vault.crypto;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class AesEncryptor {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BITS = 128;

    public EncryptionResult encrypt(String plaintext, byte[] key) {
        try {
            byte[] iv = generateIv();
            Cipher cipher = buildCipher(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes());
            return new EncryptionResult(
                    Base64.getEncoder().encodeToString(encrypted),
                    Base64.getEncoder().encodeToString(iv)
            );
        } catch (Exception e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    public String decrypt(String encryptedBase64, String ivBase64, byte[] key) {
        try {
            byte[] iv = Base64.getDecoder().decode(ivBase64);
            byte[] encrypted = Base64.getDecoder().decode(encryptedBase64);
            Cipher cipher = buildCipher(Cipher.DECRYPT_MODE, key, iv);
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted);
        } catch (Exception e) {
            throw new IllegalStateException("Decryption failed", e);
        }
    }

    private Cipher buildCipher(int mode, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec paramSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(mode, keySpec, paramSpec);
        return cipher;
    }

    private byte[] generateIv() {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public record EncryptionResult(String encryptedPassword, String iv) {}
}
