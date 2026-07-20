package dev.whflf.vault.audit;

import dev.whflf.vault.crypto.AesEncryptor;
import dev.whflf.vault.vault.VaultEntry;
import dev.whflf.vault.vault.VaultEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditServiceTest {

    @Mock private HibpClient hibpClient;
    @Mock private VaultEntryRepository vaultEntryRepository;
    @Mock private AesEncryptor aesEncryptor;

    @InjectMocks
    private AuditService auditService;

    private final byte[] aesKey = new byte[32];

    private VaultEntry entry(Long id, String encPwd, String iv) {
        return VaultEntry.builder()
                .id(id)
                .encryptedPassword(encPwd)
                .iv(iv)
                .build();
    }

    // --- isPwned ---

    @Test
    void isPwned_delegatesToHibpClient() {
        when(hibpClient.isPasswordPwned("leaked")).thenReturn(true);
        assertTrue(auditService.isPwned("leaked"));
    }

    @Test
    void isPwned_returnsFalse_whenHibpThrows() {
        when(hibpClient.isPasswordPwned(any())).thenThrow(new RuntimeException("timeout"));
        assertFalse(auditService.isPwned("any-password"));
    }

    // --- isDuplicate ---

    @Test
    void isDuplicate_returnsFalse_whenNoOtherEntries() {
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(List.of());

        assertFalse(auditService.isDuplicate(1L, 99L, "secret", aesKey));
    }

    @Test
    void isDuplicate_returnsFalse_whenOnlyEntryIsCurrentOne() {
        VaultEntry current = entry(5L, "enc", "iv");
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(List.of(current));

        assertFalse(auditService.isDuplicate(1L, 5L, "secret", aesKey));
        verifyNoInteractions(aesEncryptor);
    }

    @Test
    void isDuplicate_returnsTrue_whenOtherEntryHasSamePassword() {
        VaultEntry other = entry(2L, "enc2", "iv2");
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(List.of(other));
        when(aesEncryptor.decrypt("enc2", "iv2", aesKey)).thenReturn("secret");

        assertTrue(auditService.isDuplicate(1L, 1L, "secret", aesKey));
    }

    @Test
    void isDuplicate_returnsFalse_whenOtherEntryHasDifferentPassword() {
        VaultEntry other = entry(2L, "enc2", "iv2");
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(List.of(other));
        when(aesEncryptor.decrypt("enc2", "iv2", aesKey)).thenReturn("other-secret");

        assertFalse(auditService.isDuplicate(1L, 1L, "secret", aesKey));
    }

    @Test
    void isDuplicate_returnsFalse_whenDecryptFails() {
        VaultEntry corrupted = entry(2L, "bad-enc", "bad-iv");
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(List.of(corrupted));
        when(aesEncryptor.decrypt("bad-enc", "bad-iv", aesKey))
                .thenThrow(new IllegalStateException("Decryption failed"));

        assertFalse(auditService.isDuplicate(1L, 1L, "secret", aesKey));
    }

    @Test
    void isDuplicate_excludesCurrentEntry_andChecksRest() {
        VaultEntry current = entry(1L, "enc1", "iv1");
        VaultEntry other   = entry(2L, "enc2", "iv2");
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(List.of(current, other));
        when(aesEncryptor.decrypt("enc2", "iv2", aesKey)).thenReturn("secret");

        assertTrue(auditService.isDuplicate(1L, 1L, "secret", aesKey));
        verify(aesEncryptor, never()).decrypt(eq("enc1"), any(), any());
    }
}
