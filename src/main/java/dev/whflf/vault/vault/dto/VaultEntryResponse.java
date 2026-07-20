package dev.whflf.vault.vault.dto;

import java.time.LocalDateTime;

public record VaultEntryResponse(
        Long id,
        String site,
        String login,
        String password,
        boolean pwned,
        boolean duplicate,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {}
