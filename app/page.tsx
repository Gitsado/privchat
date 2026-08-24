"use client";

import { useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  CheckCheck,
  ChevronRight,
  Fingerprint,
  EyeOff,
  KeyRound,
  Laptop,
  LockKeyhole,
  MessageCircleMore,
  Mic2,
  SendHorizontal,
  Shield,
  ShieldCheck,
  Smartphone,
  Sparkles,
  Video,
} from "lucide-react";
import { AuthDialog } from "@/components/AuthDialog";
import { Brand } from "@/components/Brand";
import { InstallButton } from "@/components/InstallButton";

const features = [
  {
    icon: KeyRound,
    title: "Cihazda şifrələnir",
    text: "Mesaj serverə çatmamış AES‑256‑GCM ilə kilidlənir. Açıq mətn saxlanmır.",
  },
  {
    icon: Fingerprint,
    title: "Açar izi yoxlaması",
    text: "Hər cihazın ayrıca açarı və müqayisə edilə bilən təhlükəsizlik kodu var.",
  },
  {
    icon: EyeOff,
    title: "Minimum metadata",
    text: "Mesaj məzmunu, şəxsi açarlar və təhlükəsizlik kodları server tərəfindən oxunmur.",
  },
];

export default function Home() {
  const [authOpen, setAuthOpen] = useState(false);

  return (
    <main className="landing-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <header className="site-header container">
        <Brand />
        <nav aria-label="Əsas naviqasiya">
          <a href="#security">Təhlükəsizlik</a>
          <a href="#everywhere">Platformalar</a>
          <Link href="/admin">Admin</Link>
        </nav>
        <div className="header-actions">
          <InstallButton />
          <button className="button button-primary compact" onClick={() => setAuthOpen(true)}>
            Başla <ArrowRight size={16} />
          </button>
        </div>
      </header>

      <section className="hero container">
        <div className="hero-copy">
          <div className="trust-pill"><ShieldCheck size={15} /> Ucdan-uca şifrəli • Reklamsız</div>
          <h1>Söhbət səndə <span>qalır.</span></h1>
          <p>
            Məxfilik üçün qurulmuş, sürətli və gözəl mesajlaşma. PrivChat sənin
            sözlərini deyil, yalnız şifrəli məlumatı görür.
          </p>
          <div className="hero-actions">
            <button className="button button-primary large" onClick={() => setAuthOpen(true)}>
              Pulsuz başla <ArrowRight size={19} />
            </button>
            <a className="button button-ghost large" href="#security">
              Necə qorunur? <ChevronRight size={18} />
            </a>
          </div>
          <div className="hero-proof">
            <div className="proof-avatars" aria-hidden="true">
              <span>LA</span><span>EM</span><span>NK</span><span>+</span>
            </div>
            <p><strong>Sıfır mesaj izləmə</strong><br />Məzmun admin üçün də bağlıdır</p>
          </div>
        </div>

        <div className="hero-visual" aria-label="PrivChat mesajlaşma önizləməsi">
          <div className="visual-halo" />
          <div className="phone-3d">
            <div className="phone-topbar">
              <div className="mini-avatar coral">A</div>
              <div><strong>Aylin</strong><small><span /> indi aktivdir</small></div>
              <div className="phone-actions"><Video size={17} /><LockKeyhole size={15} /></div>
            </div>
            <div className="encryption-note"><ShieldCheck size={12} /> Mesajlar ucdan-uca şifrələnir</div>
            <div className="demo-messages">
              <div className="demo-message incoming">Yeni dizaynı gördün? ✨<time>20:42</time></div>
              <div className="demo-message outgoing">Hə, çox rahat görünür. Ən yaxşısı da məxfilikdir.<time>20:43 <CheckCheck size={12} /></time></div>
              <div className="voice-message incoming"><button><Mic2 size={16} /></button><span className="wave" /><b>0:18</b><time>20:44</time></div>
              <div className="typing"><i /><i /><i /></div>
            </div>
            <div className="demo-composer"><span>Mesaj yaz...</span><button><SendHorizontal size={16} /></button></div>
          </div>
          <div className="float-card float-secure"><span><Shield size={18} /></span><div><b>Qorunur</b><small>AES‑256‑GCM</small></div></div>
          <div className="float-card float-device"><span><Laptop size={18} /></span><div><b>3 cihaz</b><small>Sinxron və təhlükəsiz</small></div></div>
        </div>
      </section>

      <section className="privacy-strip">
        <div className="container privacy-grid">
          <div><strong>0</strong><span>oxunan mesaj</span></div>
          <div><strong>256</strong><span>bit AES açarı</span></div>
          <div><strong>24/7</strong><span>şifrəli bağlantı</span></div>
          <div><strong>∞</strong><span>şəxsi söhbət</span></div>
        </div>
      </section>

      <section id="security" className="section container security-section">
        <div className="section-heading centered">
          <p className="eyebrow"><Sparkles size={14} /> Məxfilik standartdır</p>
          <h2>Etibar istəmirik. <span>Riyaziyyat kifayətdir.</span></h2>
          <p>Açarlar sənin cihazında yaranır; server yalnız çatdırılmalı şifrəli paketləri saxlayır.</p>
        </div>
        <div className="feature-grid">
          {features.map(({ icon: Icon, title, text }, index) => (
            <article className="feature-card" key={title}>
              <div className={`feature-icon hue-${index}`}><Icon size={23} /></div>
              <h3>{title}</h3>
              <p>{text}</p>
              <span className="feature-number">0{index + 1}</span>
            </article>
          ))}
        </div>
        <div className="security-flow">
          <div className="flow-device"><Smartphone size={28} /><span>Sənin cihazın</span><small>Açıq mesaj</small></div>
          <div className="flow-line"><span /><LockKeyhole size={19} /><span /></div>
          <div className="flow-cloud"><ShieldCheck size={30} /><span>PrivChat serveri</span><small>Yalnız şifrəli paket</small></div>
          <div className="flow-line"><span /><LockKeyhole size={19} /><span /></div>
          <div className="flow-device"><Smartphone size={28} /><span>Dostunun cihazı</span><small>Orada açılır</small></div>
        </div>
        <p className="security-disclaimer">
          <LockKeyhole size={13} /> Kriptoqrafik nüvə açıq standartlara əsaslanır. Beta versiya müstəqil təhlükəsizlik auditindən sonra istehsal statusu alacaq.
        </p>
      </section>

      <section id="everywhere" className="section platform-section">
        <div className="container platform-card">
          <div className="platform-copy">
            <p className="eyebrow">Hər yerdə səninlə</p>
            <h2>Bir hesab. <span>Bütün ekranlar.</span></h2>
            <p>PrivChat quraşdırılan veb tətbiq kimi Windows, macOS, Android və iOS-da sürətli, tam ekranlı təcrübə verir.</p>
            <InstallButton />
            <small>Mağaza paketləri növbəti native buraxılışda gələcək.</small>
          </div>
          <div className="platform-orbit">
            <div className="orbit-ring ring-one" />
            <div className="orbit-ring ring-two" />
            <div className="orbit-core"><MessageCircleMore size={38} /></div>
            <span className="platform-node node-win">WIN</span>
            <span className="platform-node node-mac">mac</span>
            <span className="platform-node node-ios">iOS</span>
            <span className="platform-node node-android">AND</span>
          </div>
        </div>
      </section>

      <section className="cta-section container">
        <div className="cta-card">
          <div className="cta-glow" />
          <p className="eyebrow">Hazırsan?</p>
          <h2>Danış. Paylaş. <span>İz buraxma.</span></h2>
          <p>Bir dəqiqədən az vaxtda şəxsi məkanını yarat.</p>
          <button className="button button-light large" onClick={() => setAuthOpen(true)}>İndi başla <ArrowRight size={19} /></button>
        </div>
      </section>

      <footer className="site-footer container">
        <Brand compact />
        <p>© 2026 PrivChat. Məxfilik üçün hazırlanıb.</p>
        <div><a href="#security">Təhlükəsizlik</a><Link href="/chat">Veb tətbiq</Link><Link href="/admin">Admin</Link></div>
      </footer>

      <InstallButton floating />
      <AuthDialog open={authOpen} onClose={() => setAuthOpen(false)} />
    </main>
  );
}
