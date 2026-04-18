import { useState, useEffect } from "react";
import {
  prepareSend,
  confirmSend,
  cancelSend,
  TxPreview,
  validateAddressInfo,
  AddressValidationResult,
} from "../api";

interface Props {
  onBack: () => void;
}

export default function Send({ onBack }: Props) {
  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("");
  const [preview, setPreview] = useState<TxPreview | null>(null);
  const [txid, setTxid] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [addrStatus, setAddrStatus] = useState<AddressValidationResult | null>(
    null
  );

  // Live address validation with debounce
  useEffect(() => {
    if (to.length < 4) {
      setAddrStatus(null);
      return;
    }
    const timer = setTimeout(async () => {
      try {
        setAddrStatus(await validateAddressInfo(to));
      } catch {
        setAddrStatus(null);
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [to]);

  const handlePrepare = async () => {
    if (!to || !amount) return;
    if (addrStatus && !addrStatus.valid) {
      setError("Invalid recipient address");
      return;
    }
    const sat = Math.floor(parseFloat(amount) * 100_000_000);
    if (isNaN(sat) || sat <= 0) {
      setError("Invalid amount");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const p = await prepareSend(to, sat);
      setPreview(p);
    } catch (e: any) {
      setError(String(e));
    }
    setLoading(false);
  };

  const handleConfirm = async () => {
    setError("");
    setLoading(true);
    try {
      const r = await confirmSend();
      setTxid(r.txid);
    } catch (e: any) {
      setError(String(e));
    }
    setLoading(false);
  };

  const handleCancel = async () => {
    await cancelSend().catch(() => {});
    setPreview(null);
  };

  if (txid) {
    return (
      <div className="page centered">
        <h1>Transaction Sent</h1>
        <div className="card">
          <div className="success-icon">&#x2713;</div>
          <p>Transaction ID:</p>
          <code className="txid-display">{txid}</code>
        </div>
        <button className="btn-primary" onClick={onBack}>
          Back to Dashboard
        </button>
      </div>
    );
  }

  if (preview) {
    return (
      <div className="page centered">
        <h1>Confirm Transaction</h1>
        <div className="card confirm-card">
          <div className="confirm-row">
            <span>From</span>
            <span className="mono">{truncAddr(preview.from)}</span>
          </div>
          <div className="confirm-row">
            <span>To</span>
            <span className="mono">{truncAddr(preview.to)}</span>
          </div>
          <div className="confirm-row">
            <span>Amount</span>
            <span>{preview.amount_axm} AXM</span>
          </div>
          <div className="confirm-row">
            <span>Fee</span>
            <span>{(preview.fee_sat / 100_000_000).toFixed(8)} AXM</span>
          </div>
          <div className="confirm-row total">
            <span>Total</span>
            <span>{(preview.total_sat / 100_000_000).toFixed(8)} AXM</span>
          </div>
          {preview.change_sat > 0 && (
            <div className="confirm-row">
              <span>Change</span>
              <span>{(preview.change_sat / 100_000_000).toFixed(8)} AXM</span>
            </div>
          )}
        </div>
        {error && <p className="error-text">{error}</p>}
        <div className="btn-group">
          <button
            className="btn-secondary"
            onClick={handleCancel}
            disabled={loading}
          >
            Cancel
          </button>
          <button
            className="btn-primary btn-danger"
            onClick={handleConfirm}
            disabled={loading}
          >
            {loading ? "Signing & Broadcasting..." : "Sign & Send"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1>Send AXM</h1>
      </div>
      <div className="form-group">
        <label>Recipient Address</label>
        <input
          type="text"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          placeholder="axm..."
        />
        {addrStatus && addrStatus.valid && addrStatus.checksummed && (
          <span className="success-text">Valid address (checksummed)</span>
        )}
        {addrStatus && addrStatus.valid && addrStatus.legacy_format && (
          <span className="warning-text" style={{ marginBottom: 0 }}>
            Legacy address format — no checksum protection
          </span>
        )}
        {addrStatus && !addrStatus.valid && (
          <span className="error-text">
            {addrStatus.error || "Invalid address"}
          </span>
        )}
      </div>
      <div className="form-group">
        <label>Amount (AXM)</label>
        <input
          type="text"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          placeholder="0.0"
        />
      </div>
      {error && <p className="error-text">{error}</p>}
      <div className="btn-group">
        <button className="btn-secondary" onClick={onBack}>
          Cancel
        </button>
        <button
          className="btn-primary"
          disabled={loading || (addrStatus !== null && !addrStatus.valid)}
          onClick={handlePrepare}
        >
          {loading ? "Preparing..." : "Review Transaction"}
        </button>
      </div>
    </div>
  );
}

function truncAddr(a: string): string {
  if (a.length <= 20) return a;
  return a.slice(0, 12) + "..." + a.slice(-8);
}
