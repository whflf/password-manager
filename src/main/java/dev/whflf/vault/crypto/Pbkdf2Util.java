package dev.whflf.vault.crypto;

import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Component
public class Pbkdf2Util {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 100_000;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int SALT_LENGTH_BYTES = 16;

    public String generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public String deriveVerifier(String masterPassword, String saltBase64) {
        byte[] derived = derive(masterPassword, saltBase64);
        return Base64.getEncoder().encodeToString(derived);
    }

    public byte[] deriveEncryptionKey(String masterPassword, String saltBase64) {
        return derive(masterPassword, saltBase64);
    }

    public boolean verify(String masterPassword, String saltBase64, String storedVerifier) {
        String derived = deriveVerifier(masterPassword, saltBase64);
        return derived.equals(storedVerifier);
    }

    private byte[] derive(String masterPassword, String saltBase64) {
        try {
            byte[] salt = Base64.getDecoder().decode(saltBase64);
            PBEKeySpec spec = new PBEKeySpec(
                    masterPassword.toCharArray(),
                    salt,
                    ITERATIONS,
                    KEY_LENGTH_BITS
            );
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] derived = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return derived;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("PBKDF2 unavailable", e);
        }
    }
}
