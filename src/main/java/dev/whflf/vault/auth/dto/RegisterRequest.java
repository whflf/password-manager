package dev.whflf.vault.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @Email(message = "Invalid email format")
        @NotBlank(message = "Email is required")
        String email,

        @NotBlank(message = "Master password is required")
        @Size(min = 8, message = "Master password must be at least 8 characters")
        String masterPassword
) {}
