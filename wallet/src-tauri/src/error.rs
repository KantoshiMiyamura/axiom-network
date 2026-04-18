use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Wallet is locked")]
    Locked,
    #[error("Session expired — please unlock again")]
    SessionExpired,
    #[error("Too many unlock attempts. Try again in {0} seconds")]
    RateLimited(u64),
    #[error("No wallet found — create or import one first")]
    NoWallet,
    #[error("Wrong password")]
    WrongPassword,
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Insufficient funds: have {have} sat, need {need} sat")]
    InsufficientFunds { have: u64, need: u64 },
    #[error("Amount below dust threshold (minimum 546 sat)")]
    DustAmount,
    #[error("No pending transaction to confirm")]
    NoPendingTx,
    #[error("Node unreachable — operating in offline mode")]
    Offline,
    #[error("Network error: {0}")]
    Network(String),
    #[error("{0}")]
    Wallet(String),
    #[error("{0}")]
    Internal(String),
}

impl Serialize for AppError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl From<axiom_wallet::WalletError> for AppError {
    fn from(e: axiom_wallet::WalletError) -> Self {
        match e {
            axiom_wallet::WalletError::KeystoreDecryption => AppError::WrongPassword,
            axiom_wallet::WalletError::InvalidAddress => {
                AppError::InvalidAddress("invalid format".into())
            }
            axiom_wallet::WalletError::InvalidChecksum => {
                AppError::InvalidAddress("checksum mismatch".into())
            }
            other => AppError::Wallet(other.to_string()),
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Internal(format!("I/O error: {e}"))
    }
}

pub type AppResult<T> = std::result::Result<T, AppError>;
