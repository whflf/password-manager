package dev.whflf.vault.auth;

import dev.whflf.vault.auth.dto.AuthResponse;
import dev.whflf.vault.auth.dto.LoginRequest;
import dev.whflf.vault.auth.dto.RegisterRequest;
import dev.whflf.vault.crypto.Pbkdf2Util;
import dev.whflf.vault.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final Pbkdf2Util pbkdf2Util;
    private final JwtUtil jwtUtil;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already registered");
        }

        String salt = pbkdf2Util.generateSalt();
        String passwordHash = pbkdf2Util.deriveVerifier(request.masterPassword(), salt);

        User user = User.builder()
                .email(request.email())
                .passwordHash(passwordHash)
                .salt(salt)
                .build();

        userRepository.save(user);

        String token = jwtUtil.generateToken(request.email());
        return new AuthResponse(token);
    }

    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        if (!pbkdf2Util.verify(request.masterPassword(), user.getSalt(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        String token = jwtUtil.generateToken(request.email());
        return new AuthResponse(token);
    }
}
