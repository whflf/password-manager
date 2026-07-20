package dev.whflf.vault.audit;

import dev.whflf.vault.crypto.AesEncryptor;
import dev.whflf.vault.vault.VaultEntryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final HibpClient hibpClient;
    private final VaultEntryRepository vaultEntryRepository;
    private final AesEncryptor aesEncryptor;

    public boolean isPwned(String password) {
        try {
            return hibpClient.isPasswordPwned(password);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isDuplicate(Long userId, Long entryId, String password, byte[] aesKey) {
        return vaultEntryRepository.findByUserId(userId).stream()
                .filter(e -> !e.getId().equals(entryId))
                .anyMatch(e -> {
                    try {
                        return password.equals(aesEncryptor.decrypt(e.getEncryptedPassword(), e.getIv(), aesKey));
                    } catch (Exception ex) {
                        return false;
                    }
                });
    }
}
