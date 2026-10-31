import { useEffect, useRef } from "react";

interface Props {
  kind: "alert" | "confirm";
  title: string;
  message: string;
  confirmLabel?: string;
  onOk: () => void;
  onCancel: () => void;
}

/** In-app replacement for the native alert()/confirm() web prompts. */
export function Dialog({ kind, title, message, confirmLabel, onOk, onCancel }: Props) {
  const okRef = useRef<HTMLButtonElement>(null);

  // The default button is focused, so Enter activates it natively;
  // Escape closes (cancels a confirm, acknowledges an alert).
  useEffect(() => {
    okRef.current?.focus();
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") (kind === "alert" ? onOk : onCancel)();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [kind, onOk, onCancel]);

  return (
    <div className="overlay" onClick={kind === "alert" ? onOk : onCancel}>
      <div className="dialog" onClick={(e) => e.stopPropagation()}>
        <h3>{title}</h3>
        <p>{message}</p>
        <div className="dbtns">
          {kind === "confirm" && (
            <button className="btn ghost" onClick={onCancel}>
              Cancel
            </button>
          )}
          <button
            ref={okRef}
            className={`btn ${kind === "confirm" ? "danger" : "primary"}`}
            onClick={onOk}
          >
            {kind === "confirm" ? confirmLabel ?? "Confirm" : "OK"}
          </button>
        </div>
      </div>
    </div>
  );
}
