import { useEffect, useState } from "react";
import {
  getAddresses,
  AddressEntry,
  generateQr,
  newAddress,
  secureCopy,
} from "../api";

export default function Receive() {
  const [addresses, setAddresses] = useState<AddressEntry[]>([]);
  const [selected, setSelected] = useState(0);
  const [qrSvg, setQrSvg] = useState("");
  const [copied, setCopied] = useState(false);

  const load = async () => {
    try {
      const addrs = await getAddresses();
      setAddresses(addrs);
      if (addrs.length > 0) {
        const svg = await generateQr(addrs[0].address);
        setQrSvg(svg);
      }
    } catch {
      /* offline */
    }
  };

  useEffect(() => {
    load();
  }, []);

  const selectAddr = async (idx: number) => {
    setSelected(idx);
    setCopied(false);
    if (addresses[idx]) {
      const svg = await generateQr(addresses[idx].address).catch(() => "");
      setQrSvg(svg);
    }
  };

  const handleNewAddr = async () => {
    try {
      const entry = await newAddress();
      setAddresses((prev) => [...prev, entry]);
      selectAddr(addresses.length);
    } catch {
      /* err */
    }
  };

  const copyAddr = async () => {
    if (addresses[selected]) {
      try {
        await secureCopy(addresses[selected].address);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch {
        // Fallback to browser clipboard
        navigator.clipboard
          .writeText(addresses[selected].address)
          .catch(() => {});
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    }
  };

  const addr = addresses[selected]?.address ?? "";

  return (
    <div className="page">
      <div className="page-header">
        <h1>Receive AXM</h1>
      </div>

      <div className="receive-layout">
        <div
          className="qr-container"
          dangerouslySetInnerHTML={{ __html: qrSvg }}
        />
        <div className="address-display">
          <label>Your Address</label>
          <div className="address-full">{addr}</div>
          <div className="btn-group">
            <button className="btn-secondary" onClick={copyAddr}>
              {copied ? "Copied! (auto-clears in 30s)" : "Copy Address"}
            </button>
            <button className="btn-secondary" onClick={handleNewAddr}>
              New Address
            </button>
          </div>
        </div>
      </div>

      {addresses.length > 1 && (
        <div className="address-list">
          <h3>All Addresses</h3>
          {addresses.map((a, i) => (
            <div
              key={a.index}
              className={`address-item ${i === selected ? "active" : ""}`}
              onClick={() => selectAddr(i)}
            >
              <span className="addr-idx">#{a.index}</span>
              <span className="addr-mono">
                {a.address.slice(0, 16)}...{a.address.slice(-8)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
