"use client";

import { FormEvent, useState } from "react";
import { ArrowRight, Eye, EyeOff, LoaderCircle, LockKeyhole, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";

export function AuthDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const router = useRouter();
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  if (!open) return null;

  function closeDialog() {
    setMessage("");
    onClose();
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setMessage("");
    const data = new FormData(event.currentTarget);
    const email = String(data.get("email") ?? "").trim();
    const password = String(data.get("password") ?? "");
    try {
      if (mode === "signup") {
        const username = String(data.get("username") ?? "").trim().toLowerCase();
        const displayName = String(data.get("displayName") ?? "").trim();
        const { data: result, error } = await supabase.auth.signUp({
          email,
          password,
          options: {
            data: { username, display_name: displayName },
            emailRedirectTo: `${window.location.origin}/chat/`,
          },
        });
        if (error) throw error;
        if (result.session) router.replace("/chat");
        else setMessage("Təsdiq keçidini e-poçtuna göndərdik.");
      } else {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        router.replace("/chat");
      }
    } catch (error) {
      const text = error instanceof Error ? error.message : "Giriş alınmadı.";
      setMessage(text.includes("Invalid login") ? "E-poçt və ya şifrə yanlışdır." : text);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-backdrop">
      <section className="auth-card" role="dialog" aria-modal="true" aria-labelledby="auth-title">
        <button className="icon-button auth-close" onClick={closeDialog} aria-label="Bağla">
          <X size={18} />
        </button>
        <div className="auth-orb"><LockKeyhole size={30} /></div>
        <p className="eyebrow">Şəxsi məkanın</p>
        <h2 id="auth-title">{mode === "signin" ? "Yenidən xoş gəldin" : "Təhlükəsiz hesab yarat"}</h2>
        <p className="auth-subtitle">
          {mode === "signin"
            ? "Söhbətlərin yalnız sənin cihazlarında açılır."
            : "İlk cihaz açarın brauzerində yaradılacaq."}
        </p>
        <div className="auth-tabs" role="tablist">
          <button className={mode === "signin" ? "active" : ""} onClick={() => setMode("signin")}>Giriş</button>
          <button className={mode === "signup" ? "active" : ""} onClick={() => setMode("signup")}>Qeydiyyat</button>
        </div>
        <form onSubmit={submit} className="auth-form">
          {mode === "signup" && (
            <div className="form-row split">
              <label>
                <span>Görünən ad</span>
                <input name="displayName" required minLength={1} maxLength={50} placeholder="Aylin" />
              </label>
              <label>
                <span>İstifadəçi adı</span>
                <input name="username" required minLength={3} maxLength={24} pattern="[a-zA-Z0-9_]+" autoCapitalize="none" spellCheck={false} placeholder="aylin_7" />
              </label>
            </div>
          )}
          <label>
            <span>E-poçt</span>
            <input name="email" type="email" autoComplete="email" autoCapitalize="none" spellCheck={false} required placeholder="sen@example.com" />
          </label>
          <label>
            <span>Şifrə</span>
            <div className="password-field">
              <input
                name="password"
                type={showPassword ? "text" : "password"}
                autoComplete={mode === "signin" ? "current-password" : "new-password"}
                required
                minLength={12}
                placeholder="Ən az 12 simvol"
              />
              <button type="button" onClick={() => setShowPassword((value) => !value)} aria-label="Şifrəni göstər">
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </label>
          {message && <p className="form-message">{message}</p>}
          <button className="button button-primary auth-submit" disabled={loading}>
            {loading ? <LoaderCircle className="spin" size={18} /> : <>{mode === "signin" ? "Daxil ol" : "Hesab yarat"}<ArrowRight size={18} /></>}
          </button>
        </form>
        <p className="auth-legal">Davam etməklə Məxfilik və İstifadə şərtlərini qəbul edirsən.</p>
      </section>
    </div>
  );
}
