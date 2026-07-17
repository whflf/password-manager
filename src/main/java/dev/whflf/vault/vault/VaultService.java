package dev.whflf.vault.vault;

import dev.whflf.vault.audit.AuditService;
import dev.whflf.vault.auth.User;
import dev.whflf.vault.auth.UserRepository;
import dev.whflf.vault.crypto.AesEncryptor;
import dev.whflf.vault.crypto.Pbkdf2Util;
import dev.whflf.vault.vault.dto.VaultEntryRequest;
import dev.whflf.vault.vault.dto.VaultEntryResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class VaultService {

    private final VaultEntryRepository vaultEntryRepository;
    private final UserRepository userRepository;
    private final Pbkdf2Util pbkdf2Util;
    private final AesEncryptor aesEncryptor;
    private final AuditService auditService;

    @Transactional(readOnly = true)
    public List<VaultEntryResponse> getEntries(String email, String masterPassword) {
        User user = getAuthenticatedUser(email, masterPassword);
        byte[] aesKey = pbkdf2Util.deriveEncryptionKey(masterPassword, user.getSalt());

        return vaultEntryRepository.findByUserId(user.getId())
                .stream()
                .map(entry -> toResponse(entry, aesKey))
                .toList();
    }

    @Transactional
    public VaultEntryResponse createEntry(String email,
                                          String masterPassword,
                                          VaultEntryRequest request) {
        User user = getAuthenticatedUser(email, masterPassword);
        byte[] aesKey = pbkdf2Util.deriveEncryptionKey(masterPassword, user.getSalt());

        AesEncryptor.EncryptionResult encrypted =
                aesEncryptor.encrypt(request.password(), aesKey);

        VaultEntry entry = VaultEntry.builder()
                .user(user)
                .site(request.site())
                .login(request.login())
                .encryptedPassword(encrypted.encryptedPassword())
                .iv(encrypted.iv())
                .build();

        VaultEntry saved = vaultEntryRepository.save(entry);
        return toResponse(saved, aesKey);
    }

    @Transactional
    public VaultEntryResponse updateEntry(String email,
                                          String masterPassword,
                                          Long entryId,
                                          VaultEntryRequest request) {
        User user = getAuthenticatedUser(email, masterPassword);
        byte[] aesKey = pbkdf2Util.deriveEncryptionKey(masterPassword, user.getSalt());

        VaultEntry entry = vaultEntryRepository.findById(entryId)
                .filter(e -> e.getUser().getId().equals(user.getId()))
                .orElseThrow(() -> new IllegalArgumentException("Entry not found"));

        AesEncryptor.EncryptionResult encrypted =
                aesEncryptor.encrypt(request.password(), aesKey);

        entry.setSite(request.site());
        entry.setLogin(request.login());
        entry.setEncryptedPassword(encrypted.encryptedPassword());
        entry.setIv(encrypted.iv());

        return toResponse(vaultEntryRepository.save(entry), aesKey);
    }

    @Transactional
    public void deleteEntry(String email, String masterPassword, Long entryId) {
        User user = getAuthenticatedUser(email, masterPassword);

        vaultEntryRepository.findById(entryId)
                .filter(e -> e.getUser().getId().equals(user.getId()))
                .orElseThrow(() -> new IllegalArgumentException("Entry not found"));

        vaultEntryRepository.deleteById(entryId);
    }


    private User getAuthenticatedUser(String email, String masterPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!pbkdf2Util.verify(masterPassword, user.getSalt(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid master password");
        }

        return user;
    }

    private VaultEntryResponse toResponse(VaultEntry entry, byte[] aesKey) {
        String decrypted = aesEncryptor.decrypt(
                entry.getEncryptedPassword(),
                entry.getIv(),
                aesKey
        );

        return new VaultEntryResponse(
                entry.getId(),
                entry.getSite(),
                entry.getLogin(),
                decrypted,
                auditService.isPwned(decrypted),
                auditService.isDuplicate(entry.getUser().getId(), entry.getId(), decrypted),
                entry.getCreatedAt(),
                entry.getUpdatedAt()
        );
    }
}
