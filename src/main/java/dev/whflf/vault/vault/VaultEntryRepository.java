package dev.whflf.vault.vault;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface VaultEntryRepository extends JpaRepository<VaultEntry, Long> {
    List<VaultEntry> findByUserId(Long userId);
    Optional<VaultEntry> findByUserIdAndSite(Long userId, String site);
    boolean existsByUserIdAndEncryptedPassword(Long userId, String encryptedPassword);
}
