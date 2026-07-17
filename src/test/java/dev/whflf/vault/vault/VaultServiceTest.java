package dev.whflf.vault.vault;

import dev.whflf.vault.audit.AuditService;
import dev.whflf.vault.auth.User;
import dev.whflf.vault.auth.UserRepository;
import dev.whflf.vault.crypto.AesEncryptor;
import dev.whflf.vault.crypto.Pbkdf2Util;
import dev.whflf.vault.vault.dto.VaultEntryRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VaultServiceTest {

    @Mock private VaultEntryRepository vaultEntryRepository;
    @Mock private UserRepository userRepository;
    @Mock private Pbkdf2Util pbkdf2Util;
    @Mock private AesEncryptor aesEncryptor;
    @Mock private AuditService auditService;

    @InjectMocks
    private VaultService vaultService;

    private User user;
    private final byte[] aesKey = new byte[32];

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(1L)
                .email("test@mail.com")
                .passwordHash("hash")
                .salt("salt")
                .build();
    }

    @Test
    void getEntries_withValidMasterPassword_returnsDecryptedEntries() {
        VaultEntry entry = VaultEntry.builder()
                .id(1L).user(user).site("github.com")
                .login("user").encryptedPassword("enc").iv("iv")
                .build();

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));
        when(pbkdf2Util.verify("master", "salt", "hash")).thenReturn(true);
        when(pbkdf2Util.deriveEncryptionKey("master", "salt")).thenReturn(aesKey);
        when(vaultEntryRepository.findByUserId(1L)).thenReturn(List.of(entry));
        when(aesEncryptor.decrypt("enc", "iv", aesKey)).thenReturn("qwerty123");
        when(auditService.isPwned("qwerty123")).thenReturn(false);
        when(auditService.isDuplicate(1L, 1L, "qwerty123")).thenReturn(false);

        var result = vaultService.getEntries("test@mail.com", "master");

        assertEquals(1, result.size());
        assertEquals("qwerty123", result.getFirst().password());
        assertEquals("github.com", result.getFirst().site());
    }

    @Test
    void getEntries_withWrongMasterPassword_throwsException() {
        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));
        when(pbkdf2Util.verify("wrong", "salt", "hash")).thenReturn(false);

        assertThrows(IllegalArgumentException.class,
                () -> vaultService.getEntries("test@mail.com", "wrong"));

        verify(vaultEntryRepository, never()).findByUserId(any());
    }

    @Test
    void createEntry_savesEncryptedEntry() {
        AesEncryptor.EncryptionResult encrypted =
                new AesEncryptor.EncryptionResult("enc", "iv");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));
        when(pbkdf2Util.verify("master", "salt", "hash")).thenReturn(true);
        when(pbkdf2Util.deriveEncryptionKey("master", "salt")).thenReturn(aesKey);
        when(aesEncryptor.encrypt("qwerty123", aesKey)).thenReturn(encrypted);
        when(vaultEntryRepository.save(any())).thenAnswer(i -> {
            VaultEntry e = i.getArgument(0);
            e = VaultEntry.builder().id(1L).user(user)
                    .site(e.getSite()).login(e.getLogin())
                    .encryptedPassword(e.getEncryptedPassword()).iv(e.getIv())
                    .build();
            return e;
        });
        when(aesEncryptor.decrypt("enc", "iv", aesKey)).thenReturn("qwerty123");
        when(auditService.isPwned(any())).thenReturn(false);
        when(auditService.isDuplicate(any(), any(), any())).thenReturn(false);

        var result = vaultService.createEntry("test@mail.com", "master",
                new VaultEntryRequest("github.com", "user", "qwerty123"));

        assertEquals("github.com", result.site());
        assertEquals("qwerty123", result.password());
        verify(vaultEntryRepository).save(any(VaultEntry.class));
    }

    @Test
    void deleteEntry_withWrongUser_throwsException() {
        User otherUser = User.builder().id(2L).build();
        VaultEntry entry = VaultEntry.builder().id(1L).user(otherUser).build();

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));
        when(pbkdf2Util.verify("master", "salt", "hash")).thenReturn(true);
        when(vaultEntryRepository.findById(1L)).thenReturn(Optional.of(entry));

        assertThrows(IllegalArgumentException.class,
                () -> vaultService.deleteEntry("test@mail.com", "master", 1L));

        verify(vaultEntryRepository, never()).deleteById(any());
    }
}
