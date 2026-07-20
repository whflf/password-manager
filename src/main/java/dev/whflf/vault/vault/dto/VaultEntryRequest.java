package dev.whflf.vault.vault.dto;

import jakarta.validation.constraints.NotBlank;

public record VaultEntryRequest(
        @NotBlank(message = "Site is required")
        String site,

        @NotBlank(message = "Login is required")
        String login,

        @NotBlank(message = "Password is required")
        String password
) {}
