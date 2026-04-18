import { useEffect, useState } from "react";
import { getHistory, TxHistoryEntry } from "../api";

export default function History() {
  const [txs, setTxs] = useState<TxHistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try { setTxs(await getHistory()); } catch { /* offline */ }
      setLoading(false);
    })();
  }, []);

  if (loading) return <div className="page"><h1>Transaction History</h1><p>Loading...</p></div>;

  if (txs.length === 0) {
    return (
      <div className="page">
        <h1>Transaction History</h1>
        <div className="empty-state">No transactions yet</div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-header"><h1>Transaction History</h1></div>
      <div className="tx-list">
        {txs.map((tx) => (
          <div key={tx.txid} className="tx-item">
            <div className={`tx-direction ${tx.direction}`}>
              {tx.direction === "received" ? "\u2193" : "\u2191"}
            </div>
            <div className="tx-details">
              <div className="tx-amount">{tx.direction === "received" ? "+" : "-"}{tx.amount_axm} AXM</div>
              <div className="tx-meta">
                <span className="tx-id">{tx.txid.slice(0, 12)}...{tx.txid.slice(-8)}</span>
                {tx.block_height != null && <span className="tx-block">Block #{tx.block_height}</span>}
                {tx.timestamp != null && <span className="tx-time">{new Date(tx.timestamp * 1000).toLocaleString()}</span>}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
