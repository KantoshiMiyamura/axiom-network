import { useState } from "react";
import { getSeedPhrase } from "../api";

export default function Backup() {
  const [password, setPassword] = useState("");
  const [phrase, setPhrase] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const reveal = async () => {
    if (!password) return;
    setError(""); setLoading(true);
    try {
      const p = await getSeedPhrase(password);
      setPhrase(p);
    } catch (e: any) { setError(String(e)); }
    setLoading(false);
    setPassword("");
  };

  const hide = () => { setPhrase(null); setError(""); };

  if (phrase) {
    return (
      <div className="page">
        <h1>Your Seed Phrase</h1>
        <p className="warning-text">Write these words on paper. Never screenshot. Never paste into any website or app.</p>
        <div className="seed-grid">
          {phrase.split(" ").map((w, i) => (
            <div key={i} className="seed-word"><span className="seed-num">{i + 1}.</span> {w}</div>
          ))}
        </div>
        <button className="btn-secondary" onClick={hide}>Hide Seed Phrase</button>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-header"><h1>Backup Wallet</h1></div>
      <div className="card">
        <p>Your seed phrase is the master key to your wallet. If you lose it, your funds are gone forever.</p>
        <p>Enter your password to reveal the seed phrase.</p>
        <div className="form-group">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password to reveal" onKeyDown={(e) => e.key === "Enter" && reveal()} />
        </div>
        {error && <p className="error-text">{error}</p>}
        <button className="btn-primary" disabled={loading} onClick={reveal}>
          {loading ? "Authenticating..." : "Reveal Seed Phrase"}
        </button>
      </div>
    </div>
  );
}
