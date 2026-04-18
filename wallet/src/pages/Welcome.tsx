import { useState } from "react";
import { createWallet, importWalletSeed } from "../api";

interface Props { onDone: () => void }

export default function Welcome({ onDone }: Props) {
  const [mode, setMode] = useState<"choose" | "create" | "import">("choose");
  const [password, setPassword] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [phrase, setPhrase] = useState("");
  const [seedResult, setSeedResult] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  const handleCreate = async () => {
    if (password.length < 8) { setError("Password must be at least 8 characters"); return; }
    if (password !== confirmPw) { setError("Passwords do not match"); return; }
    setError(""); setLoading(true);
    try {
      const r = await createWallet(password);
      setSeedResult(r.seed_phrase);
    } catch (e: any) { setError(String(e)); } finally { setLoading(false); }
  };

  const handleImport = async () => {
    if (password.length < 8) { setError("Password must be at least 8 characters"); return; }
    if (password !== confirmPw) { setError("Passwords do not match"); return; }
    const words = phrase.trim().split(/\s+/);
    if (words.length !== 24) { setError("Seed phrase must be exactly 24 words"); return; }
    setError(""); setLoading(true);
    try {
      await importWalletSeed(phrase.trim(), password);
      onDone();
    } catch (e: any) { setError(String(e)); } finally { setLoading(false); }
  };

  if (seedResult) {
    return (
      <div className="page centered">
        <h1>Save Your Seed Phrase</h1>
        <p className="warning-text">Write these 24 words down on paper. Never share them. Never store them digitally. This is the ONLY way to recover your wallet.</p>
        <div className="seed-grid">
          {seedResult.split(" ").map((w, i) => (
            <div key={i} className="seed-word"><span className="seed-num">{i + 1}.</span> {w}</div>
          ))}
        </div>
        <label className="checkbox-label">
          <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
          I have written down my seed phrase and stored it securely
        </label>
        <button className="btn-primary" disabled={!confirmed} onClick={onDone}>
          Continue to Wallet
        </button>
      </div>
    );
  }

  if (mode === "choose") {
    return (
      <div className="page centered">
        <div className="logo-large">AXIOM</div>
        <h1>Welcome to Axiom Wallet</h1>
        <p className="subtitle">Post-quantum secure. Non-custodial. Your keys, your coins.</p>
        <div className="btn-group-vertical">
          <button className="btn-primary" onClick={() => setMode("create")}>Create New Wallet</button>
          <button className="btn-secondary" onClick={() => setMode("import")}>Import Seed Phrase</button>
        </div>
      </div>
    );
  }

  return (
    <div className="page centered">
      <h1>{mode === "create" ? "Create New Wallet" : "Import Wallet"}</h1>
      {mode === "import" && (
        <div className="form-group">
          <label>Seed Phrase (24 words)</label>
          <textarea className="seed-input" rows={4} value={phrase} onChange={(e) => setPhrase(e.target.value)}
            placeholder="word1 word2 word3 ... word24" />
        </div>
      )}
      <div className="form-group">
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
          placeholder="Minimum 8 characters, mixed case, digits, symbols" />
      </div>
      <div className="form-group">
        <label>Confirm Password</label>
        <input type="password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)}
          placeholder="Re-enter password" />
      </div>
      {error && <p className="error-text">{error}</p>}
      <div className="btn-group">
        <button className="btn-secondary" onClick={() => { setMode("choose"); setError(""); }}>Back</button>
        <button className="btn-primary" disabled={loading} onClick={mode === "create" ? handleCreate : handleImport}>
          {loading ? "Working..." : mode === "create" ? "Create Wallet" : "Import Wallet"}
        </button>
      </div>
    </div>
  );
}
