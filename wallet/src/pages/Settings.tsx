import { useEffect, useState } from "react";
import {
  getSettings,
  setNodeUrl,
  setLockTimeout,
  lockWallet,
  getNetworkStatus,
  NetworkStatus,
  getIntegrityInfo,
  IntegrityInfo,
} from "../api";

interface Props {
  onLock: () => void;
}

export default function Settings({ onLock }: Props) {
  const [nodeUrl, setNodeUrlLocal] = useState("");
  const [timeoutSecs, setTimeoutSecs] = useState(300);
  const [status, setStatus] = useState<NetworkStatus | null>(null);
  const [integrity, setIntegrity] = useState<IntegrityInfo | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const [s, n, i] = await Promise.all([
          getSettings(),
          getNetworkStatus(),
          getIntegrityInfo(),
        ]);
        setNodeUrlLocal(s.node_url);
        setTimeoutSecs(s.lock_timeout_secs);
        setStatus(n);
        setIntegrity(i);
      } catch {
        /* ignore */
      }
    })();
  }, []);

  const saveUrl = async () => {
    try {
      await setNodeUrl(nodeUrl);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e: any) {
      setError(String(e));
    }
  };

  const saveTimeout = async () => {
    try {
      await setLockTimeout(timeoutSecs);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e: any) {
      setError(String(e));
    }
  };

  const handleLock = async () => {
    await lockWallet();
    onLock();
  };

  const testConnection = async () => {
    try {
      setStatus(await getNetworkStatus());
    } catch {
      /* */
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1>Settings</h1>
      </div>

      <div className="card">
        <h3>Node Connection</h3>
        <div className="form-group">
          <label>RPC URL</label>
          <input
            type="text"
            value={nodeUrl}
            onChange={(e) => setNodeUrlLocal(e.target.value)}
          />
        </div>
        <div className="btn-group">
          <button className="btn-secondary" onClick={testConnection}>
            Test Connection
          </button>
          <button className="btn-primary" onClick={saveUrl}>
            Save
          </button>
        </div>
        {status && (
          <div className="status-inline">
            <span className="status-dot" data-online={status.online} />
            {status.online
              ? `Connected — Block #${status.block_height?.toLocaleString()}, ${status.peer_count} peers`
              : "Offline"}
          </div>
        )}
      </div>

      <div className="card">
        <h3>Auto-Lock Timeout</h3>
        <div className="form-group">
          <label>Lock after (seconds)</label>
          <input
            type="number"
            min={30}
            value={timeoutSecs}
            onChange={(e) => setTimeoutSecs(Number(e.target.value))}
          />
        </div>
        <button className="btn-primary" onClick={saveTimeout}>
          Save
        </button>
      </div>

      {saved && <p className="success-text">Settings saved</p>}
      {error && <p className="error-text">{error}</p>}

      <div className="card">
        <h3>Security Status</h3>
        {integrity && (
          <div style={{ fontSize: 13 }}>
            <div
              style={{
                display: "flex",
                gap: 8,
                alignItems: "center",
                marginBottom: 8,
              }}
            >
              <span
                className="status-dot"
                data-online={integrity.device_protection}
              />
              <span>
                OS Key Protection (DPAPI / Keychain / Secret Service):{" "}
                {integrity.device_protection ? "Active" : "Unavailable"}
              </span>
            </div>
            <div
              style={{
                display: "flex",
                gap: 8,
                alignItems: "center",
                marginBottom: 8,
              }}
            >
              <span
                className="status-dot"
                data-online={integrity.cache_encrypted}
              />
              <span>
                Cache Encryption:{" "}
                {integrity.cache_encrypted ? "Encrypted" : "Plaintext"}
              </span>
            </div>
            {integrity.binary_hash && (
              <div style={{ marginTop: 12 }}>
                <label style={{ color: "var(--text-dim)", fontSize: 12 }}>
                  Binary SHA-256
                </label>
                <div className="address-full" style={{ fontSize: 11 }}>
                  {integrity.binary_hash}
                </div>
              </div>
            )}
            {integrity.keystore_hash && (
              <div style={{ marginTop: 8 }}>
                <label style={{ color: "var(--text-dim)", fontSize: 12 }}>
                  Keystore SHA-256
                </label>
                <div className="address-full" style={{ fontSize: 11 }}>
                  {integrity.keystore_hash}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="card">
        <h3>Wallet</h3>
        <button className="btn-danger" onClick={handleLock}>
          Lock Wallet Now
        </button>
      </div>
    </div>
  );
}
