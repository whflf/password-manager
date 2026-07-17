package dev.whflf.vault.audit;

import org.springframework.stereotype.Service;

@Service
public class AuditService {

    public boolean isPwned(String password) {
        return false; // TODO: implement HaveIBeenPwned check
    }

    public boolean isDuplicate(Long userId, Long entryId, String password) {
        return false; // TODO: implement duplicate check
    }
}
