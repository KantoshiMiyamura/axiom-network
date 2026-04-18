import { invoke } from "@tauri-apps/api/core";

// ── Wallet lifecycle ────────────────────────────────────────────────────────

export interface CreateResult {
  seed_phrase: string;
  address: string;
}
export interface ImportResult {
  address: string;
}
export interface UnlockResult {
  address: string;
  account_count: number;
}
export interface SessionStatus {
  locked: boolean;
  remaining_secs: number;
}

export const walletExists = () => invoke<boolean>("wallet_exists");
export const createWallet = (password: string) =>
  invoke<CreateResult>("create_wallet", { password });
export const importWalletSeed = (phrase: string, password: string) =>
  invoke<ImportResult>("import_wallet_seed", { phrase, password });
export const unlockWallet = (password: string) =>
  invoke<UnlockResult>("unlock_wallet", { password });
export const lockWallet = () => invoke<void>("lock_wallet");
export const checkSession = () => invoke<SessionStatus>("check_session");
export const getSeedPhrase = (password: string) =>
  invoke<string>("get_seed_phrase", { password });

// ── Account ─────────────────────────────────────────────────────────────────

export interface AddressEntry {
  index: number;
  address: string;
}
export interface BalanceInfo {
  total_sat: number;
  total_axm: string;
  address: string;
  from_cache: boolean;
}

export const getAddresses = () => invoke<AddressEntry[]>("get_addresses");
export const newAddress = () => invoke<AddressEntry>("new_address");
export const refreshBalance = () => invoke<BalanceInfo>("refresh_balance");
export const getCachedBalance = () => invoke<BalanceInfo>("get_cached_balance");

// ── Transactions ────────────────────────────────────────────────────────────

export interface TxPreview {
  from: string;
  to: string;
  amount_sat: number;
  amount_axm: string;
  fee_sat: number;
  total_sat: number;
  change_sat: number;
}
export interface SendResult {
  txid: string;
}
export interface TxHistoryEntry {
  txid: string;
  block_height: number | null;
  timestamp: number | null;
  value_change: number;
  direction: string;
  amount_axm: string;
}

export const prepareSend = (to: string, amountSat: number) =>
  invoke<TxPreview>("prepare_send", { to, amountSat });
export const confirmSend = () => invoke<SendResult>("confirm_send");
export const cancelSend = () => invoke<void>("cancel_send");
export const getHistory = () => invoke<TxHistoryEntry[]>("get_history");
export const signOffline = (unsignedHex: string) =>
  invoke<string>("sign_offline", { unsignedHex });

// ── Settings ────────────────────────────────────────────────────────────────

export interface WalletSettings {
  node_url: string;
  lock_timeout_secs: number;
}
export interface NetworkStatus {
  online: boolean;
  block_height: number | null;
  peer_count: number | null;
  node_url: string;
}

export const getSettings = () => invoke<WalletSettings>("get_settings");
export const setNodeUrl = (url: string) =>
  invoke<void>("set_node_url", { url });
export const setLockTimeout = (secs: number) =>
  invoke<void>("set_lock_timeout", { secs });
export const getNetworkStatus = () =>
  invoke<NetworkStatus>("get_network_status");
export const generateQr = (data: string) =>
  invoke<string>("generate_qr", { data });

// ── Security ───────────────────────────────────────────────────────────────

export interface AddressValidationResult {
  valid: boolean;
  checksummed: boolean;
  legacy_format: boolean;
  error: string | null;
}

export interface IntegrityInfo {
  binary_hash: string | null;
  keystore_hash: string | null;
  device_protection: boolean;
  cache_encrypted: boolean;
}

export const secureCopy = (text: string, clearAfterMs?: number) =>
  invoke<void>("secure_copy", { text, clearAfterMs });
export const validateAddressInfo = (address: string) =>
  invoke<AddressValidationResult>("validate_address_info", { address });
export const getIntegrityInfo = () =>
  invoke<IntegrityInfo>("get_integrity_info");
export const clearAccountCache = (address: string) =>
  invoke<void>("clear_account_cache", { address });
