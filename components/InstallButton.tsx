"use client";

import { useEffect, useState } from "react";
import { Download, MonitorDown, Share, X } from "lucide-react";

type InstallPromptEvent = Event & {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
};

export function InstallButton({ floating = false }: { floating?: boolean }) {
  const [prompt, setPrompt] = useState<InstallPromptEvent | null>(null);
  const [showHelp, setShowHelp] = useState(false);

  useEffect(() => {
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("/sw.js").catch(() => undefined);
    }
    const onPrompt = (event: Event) => {
      event.preventDefault();
      setPrompt(event as InstallPromptEvent);
    };
    window.addEventListener("beforeinstallprompt", onPrompt);
    return () => window.removeEventListener("beforeinstallprompt", onPrompt);
  }, []);

  async function install() {
    if (prompt) {
      await prompt.prompt();
      const choice = await prompt.userChoice;
      if (choice.outcome === "accepted") setPrompt(null);
      return;
    }
    setShowHelp(true);
  }

  return (
    <>
      <button
        className={floating ? "install-fab" : "button button-ghost install-inline"}
        onClick={install}
        type="button"
      >
        {floating ? <Download size={20} /> : <MonitorDown size={17} />}
        <span>{floating ? "Tətbiqi endir" : "Quraşdır"}</span>
      </button>
      {showHelp && (
        <div className="install-sheet-backdrop">
          <div className="install-sheet" role="dialog" aria-modal="true" aria-labelledby="install-title">
            <button
              className="icon-button sheet-close"
              onClick={() => setShowHelp(false)}
              aria-label="Bağla"
            >
              <X size={18} />
            </button>
            <span className="install-sheet-icon"><Share size={24} /></span>
            <p className="eyebrow">Cihazına əlavə et</p>
            <h3 id="install-title">PrivChat hər yerdə yanında</h3>
            <p>
              Brauzerin menyusunu aç və <b>“Install app”</b> seç. iPhone və
              iPad-də Paylaş düyməsinə toxunub <b>“Add to Home Screen”</b> seç.
            </p>
          </div>
        </div>
      )}
    </>
  );
}
