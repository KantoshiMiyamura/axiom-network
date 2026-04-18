import { useEffect, useState } from "react";
import { walletExists, checkSession, SessionStatus } from "./api";

import Welcome from "./pages/Welcome";
import Unlock from "./pages/Unlock";
import Dashboard from "./pages/Dashboard";
import Send from "./pages/Send";
import Receive from "./pages/Receive";
import History from "./pages/History";
import Backup from "./pages/Backup";
import Settings from "./pages/Settings";

type Page = "welcome" | "unlock" | "dashboard" | "send" | "receive" | "history" | "backup" | "settings";

export default function App() {
  const [page, setPage] = useState<Page>("welcome");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const exists = await walletExists();
        if (!exists) {
          setPage("welcome");
        } else {
          const status: SessionStatus = await checkSession();
          setPage(status.locked ? "unlock" : "dashboard");
        }
      } catch {
        setPage("welcome");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  // Session watchdog — auto-lock on timeout
  useEffect(() => {
    if (page === "welcome" || page === "unlock") return;
    const iv = setInterval(async () => {
      try {
        const s = await checkSession();
        if (s.locked) setPage("unlock");
      } catch { /* ignore */ }
    }, 15_000);
    return () => clearInterval(iv);
  }, [page]);

  if (loading) {
    return <div className="loading-screen"><div className="spinner" /><p>Loading...</p></div>;
  }

  const nav = (p: Page) => setPage(p);

  const sidebar = page !== "welcome" && page !== "unlock" ? (
    <nav className="sidebar">
      <div className="sidebar-brand">AXIOM</div>
      <button className={page === "dashboard" ? "active" : ""} onClick={() => nav("dashboard")}>Dashboard</button>
      <button className={page === "send" ? "active" : ""} onClick={() => nav("send")}>Send</button>
      <button className={page === "receive" ? "active" : ""} onClick={() => nav("receive")}>Receive</button>
      <button className={page === "history" ? "active" : ""} onClick={() => nav("history")}>History</button>
      <button className={page === "backup" ? "active" : ""} onClick={() => nav("backup")}>Backup</button>
      <button className={page === "settings" ? "active" : ""} onClick={() => nav("settings")}>Settings</button>
    </nav>
  ) : null;

  let content: JSX.Element;
  switch (page) {
    case "welcome":   content = <Welcome onDone={() => nav("dashboard")} />; break;
    case "unlock":    content = <Unlock onUnlock={() => nav("dashboard")} />; break;
    case "dashboard": content = <Dashboard onNav={nav} />; break;
    case "send":      content = <Send onBack={() => nav("dashboard")} />; break;
    case "receive":   content = <Receive />; break;
    case "history":   content = <History />; break;
    case "backup":    content = <Backup />; break;
    case "settings":  content = <Settings onLock={() => nav("unlock")} />; break;
  }

  return (
    <div className="app-layout">
      {sidebar}
      <main className="main-content">{content}</main>
    </div>
  );
}
