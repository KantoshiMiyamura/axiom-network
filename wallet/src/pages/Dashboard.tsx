import { useEffect, useState } from "react";
import { refreshBalance, BalanceInfo, getNetworkStatus, NetworkStatus } from "../api";

interface Props { onNav: (page: any) => void }

export default function Dashboard({ onNav }: Props) {
  const [balance, setBalance] = useState<BalanceInfo | null>(null);
  const [network, setNetwork] = useState<NetworkStatus | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const loadData = async () => {
    setRefreshing(true);
    try {
      const [b, n] = await Promise.all([refreshBalance(), getNetworkStatus()]);
      setBalance(b);
      setNetwork(n);
    } catch { /* offline fallback handled by backend */ }
    setRefreshing(false);
  };

  useEffect(() => { loadData(); }, []);

  return (
    <div className="page">
      <div className="page-header">
        <h1>Dashboard</h1>
        <button className="btn-icon" onClick={loadData} disabled={refreshing} title="Refresh">
          {refreshing ? "..." : "\u21BB"}
        </button>
      </div>

      <div className="card balance-card">
        <div className="balance-label">Total Balance</div>
        <div className="balance-amount">{balance?.total_axm ?? "..."} AXM</div>
        <div className="balance-sub">{balance ? `${balance.total_sat.toLocaleString()} sat` : ""}</div>
        {balance?.from_cache && <span className="badge badge-warn">cached</span>}
      </div>

      <div className="card-row">
        <div className="card status-card">
          <div className="status-dot" data-online={network?.online ?? false} />
          <div>
            <div className="status-label">{network?.online ? "Online" : "Offline"}</div>
            {network?.block_height != null && <div className="status-sub">Block #{network.block_height.toLocaleString()}</div>}
            {network?.peer_count != null && <div className="status-sub">{network.peer_count} peers</div>}
          </div>
        </div>

        <div className="card address-card">
          <div className="address-label">Primary Address</div>
          <div className="address-mono">{balance?.address ? truncAddr(balance.address) : "..."}</div>
        </div>
      </div>

      <div className="btn-group">
        <button className="btn-primary" onClick={() => onNav("send")}>Send</button>
        <button className="btn-secondary" onClick={() => onNav("receive")}>Receive</button>
        <button className="btn-secondary" onClick={() => onNav("history")}>History</button>
      </div>
    </div>
  );
}

function truncAddr(a: string): string {
  if (a.length <= 20) return a;
  return a.slice(0, 12) + "..." + a.slice(-8);
}
