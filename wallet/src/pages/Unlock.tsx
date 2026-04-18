import { useState } from "react";
import { unlockWallet } from "../api";

interface Props { onUnlock: () => void }

export default function Unlock({ onUnlock }: Props) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleUnlock = async () => {
    if (!password) return;
    setError(""); setLoading(true);
    try {
      await unlockWallet(password);
      onUnlock();
    } catch (e: any) {
      setError(String(e));
    } finally {
      setLoading(false);
      setPassword("");
    }
  };

  const onKey = (e: React.KeyboardEvent) => { if (e.key === "Enter") handleUnlock(); };

  return (
    <div className="page centered">
      <div className="logo-large">AXIOM</div>
      <h1>Unlock Wallet</h1>
      <div className="form-group" style={{ maxWidth: 400 }}>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
          onKeyDown={onKey} placeholder="Enter your password" autoFocus />
      </div>
      {error && <p className="error-text">{error}</p>}
      <button className="btn-primary" disabled={loading} onClick={handleUnlock}>
        {loading ? "Decrypting..." : "Unlock"}
      </button>
    </div>
  );
}
