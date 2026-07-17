package dev.whflf.vault.auth;

import dev.whflf.vault.auth.dto.LoginRequest;
import dev.whflf.vault.auth.dto.RegisterRequest;
import dev.whflf.vault.crypto.Pbkdf2Util;
import dev.whflf.vault.security.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private Pbkdf2Util pbkdf2Util;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthService authService;

    @Test
    void register_withNewEmail_returnsToken() {
        when(userRepository.existsByEmail("test@mail.com")).thenReturn(false);
        when(pbkdf2Util.generateSalt()).thenReturn("salt");
        when(pbkdf2Util.deriveVerifier("password123", "salt")).thenReturn("hash");
        when(userRepository.save(any())).thenReturn(new User());
        when(jwtUtil.generateToken("test@mail.com")).thenReturn("jwt-token");

        var response = authService.register(new RegisterRequest("test@mail.com", "password123"));

        assertEquals("jwt-token", response.token());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void register_withExistingEmail_throwsException() {
        when(userRepository.existsByEmail("test@mail.com")).thenReturn(true);

        assertThrows(IllegalArgumentException.class,
                () -> authService.register(new RegisterRequest("test@mail.com", "password123")));

        verify(userRepository, never()).save(any());
    }

    @Test
    void login_withValidCredentials_returnsToken() {
        User user = User.builder()
                .email("test@mail.com")
                .passwordHash("hash")
                .salt("salt")
                .build();

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));
        when(pbkdf2Util.verify("password123", "salt", "hash")).thenReturn(true);
        when(jwtUtil.generateToken("test@mail.com")).thenReturn("jwt-token");

        var response = authService.login(new LoginRequest("test@mail.com", "password123"));

        assertEquals("jwt-token", response.token());
    }

    @Test
    void login_withWrongPassword_throwsException() {
        User user = User.builder()
                .email("test@mail.com")
                .passwordHash("hash")
                .salt("salt")
                .build();

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));
        when(pbkdf2Util.verify("wrong", "salt", "hash")).thenReturn(false);

        assertThrows(IllegalArgumentException.class,
                () -> authService.login(new LoginRequest("test@mail.com", "wrong")));
    }

    @Test
    void login_withUnknownEmail_throwsException() {
        when(userRepository.findByEmail("unknown@mail.com")).thenReturn(Optional.empty());

        assertThrows(IllegalArgumentException.class,
                () -> authService.login(new LoginRequest("unknown@mail.com", "password123")));
    }
}
