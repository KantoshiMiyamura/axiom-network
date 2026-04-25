use std::time::{Duration, Instant};

const MAX_ATTEMPTS: u32 = 5;
const BASE_LOCKOUT_SECS: u64 = 30;
const MAX_EXPONENT: u32 = 6;
const CLIPBOARD_CLEAR_MS: u64 = 30_000;

// ── Rate limiter ───────────────────────────────────────────────────────────

pub struct UnlockRateLimiter {
    failures: u32,
    locked_until: Option<Instant>,
}

impl UnlockRateLimiter {
    pub fn new() -> Self {
        Self {
            failures: 0,
            locked_until: None,
        }
    }

    pub fn check(&self) -> Result<(), u64> {
        if let Some(until) = self.locked_until {
            let now = Instant::now();
            if now < until {
                return Err((until - now).as_secs() + 1);
            }
        }
        Ok(())
    }

    pub fn record_failure(&mut self) -> Option<u64> {
        self.failures += 1;
        if self.failures >= MAX_ATTEMPTS {
            let exp = (self.failures - MAX_ATTEMPTS).min(MAX_EXPONENT);
            let secs = BASE_LOCKOUT_SECS * 2u64.pow(exp);
            self.locked_until = Some(Instant::now() + Duration::from_secs(secs));
            Some(secs)
        } else {
            None
        }
    }

    pub fn record_success(&mut self) {
        self.failures = 0;
        self.locked_until = None;
    }
}

// ── File permissions ───────────────────────────────────────────────────────

#[cfg(unix)]
pub fn set_keystore_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
pub fn set_keystore_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

// ── File integrity ─────────────────────────────────────────────────────────

pub fn file_checksum(path: &std::path::Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path).ok()?;
    Some(hex::encode(Sha256::digest(&data)))
}

/// SHA-256 of the running binary for integrity verification.
pub fn binary_checksum() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    file_checksum(&exe)
}

// ── Clipboard protection ───────────────────────────────────────────────────

/// Copy text to clipboard and spawn a thread to clear it after timeout.
pub fn clipboard_copy_and_clear(text: &str, clear_after_ms: Option<u64>) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| format!("clipboard init: {e}"))?;
    clipboard
        .set_text(text)
        .map_err(|e| format!("clipboard set: {e}"))?;

    let timeout = clear_after_ms.unwrap_or(CLIPBOARD_CLEAR_MS);
    let expected = text.to_string();

    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(timeout));
        if let Ok(mut cb) = arboard::Clipboard::new() {
            if cb.get_text().map(|t| t == expected).unwrap_or(false) {
                let _ = cb.set_text(String::new());
            }
        }
    });

    Ok(())
}
