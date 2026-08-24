"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  CircleUserRound,
  Database,
  Download,
  FileClock,
  Flag,
  Gauge,
  KeyRound,
  LayoutDashboard,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Menu,
  MessageSquareText,
  RefreshCw,
  Search,
  ShieldCheck,
  Users,
  X,
  XCircle,
} from "lucide-react";
import { Brand } from "@/components/Brand";
import { supabase } from "@/lib/supabase";

type Metrics = {
  users: number;
  active_today: number;
  messages_today: number;
  open_reports: number;
  devices: number;
  verified_devices: number;
  blocks: number;
};

type AdminProfile = {
  id: string;
  username: string;
  display_name: string;
  role: string;
  last_seen: string;
  created_at: string;
  suspended_until: string | null;
};

type AuditLog = {
  id: number;
  action: string;
  entity_type: string;
  entity_id: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  actor_id: string | null;
};

type Report = {
  id: string;
  reason: string;
  status: "open" | "reviewing" | "resolved" | "dismissed";
  created_at: string;
  conversation_id: string | null;
  reporter: { username: string; display_name: string } | null;
  reported: { username: string; display_name: string } | null;
};

const actionLabels: Record<string, string> = {
  "account.created": "Yeni hesab yaradıldı",
  "conversation.created": "Söhbət yaradıldı",
  "message.sent": "Şifrəli mesaj çatdırıldı",
  "message.deleted": "Mesaj paketi silindi",
  "user.blocked": "İstifadəçi bloklandı",
  "user.unblocked": "İstifadəçi bloku açıldı",
  "user.suspended": "İstifadəçi dayandırıldı",
  "user.unsuspended": "İstifadəçi bərpa edildi",
  "report.reviewing": "Şikayət baxışa götürüldü",
  "report.resolved": "Şikayət həll edildi",
  "report.dismissed": "Şikayət rədd edildi",
};

function relative(value: string) {
  const minutes = Math.max(0, Math.round((Date.now() - +new Date(value)) / 60_000));
  if (minutes < 1) return "indi";
  if (minutes < 60) return `${minutes} dəq əvvəl`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)} saat əvvəl`;
  return `${Math.floor(minutes / 1440)} gün əvvəl`;
}

function csvCell(value: unknown) {
  let text = typeof value === "string" ? value : JSON.stringify(value ?? "");
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

export function AdminDashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [users, setUsers] = useState<AdminProfile[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [profile, setProfile] = useState<AdminProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [allowed, setAllowed] = useState<boolean | null>(null);
  const [healthy, setHealthy] = useState(false);
  const [notice, setNotice] = useState("");
  const [search, setSearch] = useState("");
  const [durationDays, setDurationDays] = useState(30);
  const [mobileMenu, setMobileMenu] = useState(false);

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    const { data: session } = await supabase.auth.getSession();
    const account = session.session?.user;
    if (!account) { setAllowed(false); setLoading(false); return; }

    const { data: ownProfile, error: ownError } = await supabase
      .from("profiles")
      .select("id,username,display_name,role,last_seen,created_at,suspended_until")
      .eq("id", account.id)
      .single();
    if (ownError) {
      setNotice("Hesab profili və ya məlumat sxemi tapılmadı.");
      setAllowed(false);
      setLoading(false);
      return;
    }
    setProfile(ownProfile as AdminProfile);
    if (!["admin", "moderator"].includes(ownProfile.role)) { setAllowed(false); setLoading(false); return; }
    setAllowed(true);

    const [metricResult, userResult, logResult, reportResult] = await Promise.all([
      supabase.rpc("get_admin_metrics"),
      supabase.from("profiles").select("id,username,display_name,role,last_seen,created_at,suspended_until").order("created_at", { ascending: false }).limit(100),
      supabase.from("audit_logs").select("id,action,entity_type,entity_id,metadata,created_at,actor_id").order("created_at", { ascending: false }).limit(100),
      supabase
        .from("reports")
        .select("id,reason,status,created_at,conversation_id,reporter:profiles!reports_reporter_id_fkey(username,display_name),reported:profiles!reports_reported_user_id_fkey(username,display_name)")
        .in("status", ["open", "reviewing"])
        .order("created_at", { ascending: false })
        .limit(30),
    ]);
    const errors = [metricResult.error, userResult.error, logResult.error, reportResult.error].filter(Boolean);
    setHealthy(errors.length === 0);
    if (errors.length) setNotice("Bəzi idarəetmə məlumatları yüklənmədi. Təhlükəsizlik miqrasiyasını yoxla.");
    else setNotice("");
    setMetrics((metricResult.data ?? null) as Metrics | null);
    setUsers((userResult.data ?? []) as AdminProfile[]);
    setLogs((logResult.data ?? []) as AuditLog[]);
    setReports((reportResult.data ?? []) as unknown as Report[]);
    setLoading(false);
  }, []);

  useEffect(() => {
    // Initial admin permission and data boundary.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadDashboard();
  }, [loadDashboard]);

  async function toggleSuspension(target: AdminProfile) {
    const suspend = !target.suspended_until;
    const { error } = await supabase.rpc("admin_set_suspension", { target_user: target.id, suspend, duration_days: durationDays });
    if (error) setNotice(error.message);
    else loadDashboard();
  }

  async function resolveReport(target: Report, status: "reviewing" | "resolved" | "dismissed") {
    const { error } = await supabase.rpc("admin_resolve_report", { target_report: target.id, new_status: status, note: "" });
    if (error) setNotice(error.message);
    else loadDashboard();
  }

  function exportAudit() {
    const header = ["id", "created_at", "actor_id", "action", "entity_type", "entity_id", "metadata"];
    const body = logs.map((log) => [log.id, log.created_at, log.actor_id, log.action, log.entity_type, log.entity_id, log.metadata].map(csvCell).join(","));
    const blob = new Blob(["\uFEFF" + [header.join(","), ...body].join("\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `privchat-audit-${new Date().toISOString().slice(0, 10)}.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  const normalizedSearch = search.toLowerCase();
  const visibleUsers = useMemo(() => users.filter((item) => `${item.display_name} ${item.username} ${item.id}`.toLowerCase().includes(normalizedSearch)), [normalizedSearch, users]);
  const visibleLogs = useMemo(() => logs.filter((item) => `${item.action} ${item.entity_type} ${item.entity_id ?? ""}`.toLowerCase().includes(normalizedSearch)), [logs, normalizedSearch]);

  if (loading && allowed === null) return <main className="admin-gate"><LoaderCircle className="spin" size={30} /><p>İcazələr yoxlanılır...</p></main>;

  if (allowed === false) return <main className="gate-screen"><div className="gate-card admin-denied"><div className="auth-orb warning"><LockKeyhole size={29} /></div><Brand /><h1>Admin icazəsi tələb olunur</h1><p>{notice || "Bu panel yalnız admin və moderator hesabları üçün açıqdır."}</p><div className="gate-actions"><Link className="button button-primary" href="/">Ana səhifə</Link><Link className="button button-ghost" href="/chat">Mesajlara keç</Link></div></div></main>;

  const cards = [
    { label: "Ümumi istifadəçi", value: metrics?.users ?? 0, delta: `${metrics?.active_today ?? 0} bu gün aktiv`, icon: Users, tone: "violet" },
    { label: "Bugünkü mesaj", value: metrics?.messages_today ?? 0, delta: "məzmun görünmür", icon: MessageSquareText, tone: "blue" },
    { label: "İmzalı cihaz", value: metrics?.verified_devices ?? 0, delta: `${metrics?.devices ?? 0} aktiv cihaz`, icon: KeyRound, tone: "green" },
    { label: "Açıq şikayət", value: metrics?.open_reports ?? 0, delta: `${metrics?.blocks ?? 0} istifadəçi bloku`, icon: AlertTriangle, tone: "orange" },
  ];

  return (
    <main className="admin-shell">
      <aside className={`admin-sidebar ${mobileMenu ? "open" : ""}`}>
        <div className="admin-brand"><Brand compact /><button className="icon-button mobile-only" onClick={() => setMobileMenu(false)}><X size={18} /></button></div>
        <p className="admin-nav-label">İDARƏETMƏ</p>
        <nav className="admin-nav"><a className="active" href="#overview"><LayoutDashboard size={18} /> İcmal</a><a href="#reports"><Flag size={18} /> Şikayətlər</a><a href="#users"><Users size={18} /> İstifadəçilər</a><a href="#audit"><FileClock size={18} /> Audit logları</a><a href="#system"><Database size={18} /> Sistem</a></nav>
        <div className="admin-security-badge"><ShieldCheck size={20} /><div><b>Mesaj məzmunu bağlıdır</b><small>Moderasiya yalnız metadata və şikayət səbəbini görür</small></div></div>
        <div className="admin-user"><span>{profile?.display_name?.[0] ?? "A"}</span><div><b>{profile?.display_name}</b><small>{profile?.role}</small></div><button onClick={() => supabase.auth.signOut()} className="icon-button"><LogOut size={17} /></button></div>
      </aside>

      <section className="admin-content">
        <header className="admin-topbar"><button className="icon-button mobile-only" onClick={() => setMobileMenu(true)}><Menu size={20} /></button><div className="admin-search"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="İstifadəçi, hadisə və ya ID axtar..." /></div><div className={`system-live ${healthy ? "" : "warning"}`}><i /> {healthy ? "Cari yoxlama uğurludur" : "Yoxlama tələb olunur"}</div><button className="admin-profile-button"><span>{profile?.display_name?.[0]}</span></button></header>

        <div className="admin-main" id="overview">
          <div className="admin-title-row"><div><p className="eyebrow">İDARƏETMƏ İCMALI</p><h1>Sabahın xeyir, {profile?.display_name?.split(" ")[0]}</h1><p>PrivChat şəbəkəsinin cari idarəetmə və təhlükəsizlik vəziyyəti.</p></div><button className="button button-ghost" onClick={loadDashboard}><RefreshCw size={16} className={loading ? "spin" : ""} /> Yenilə</button></div>
          {notice && <div className="admin-notice"><AlertTriangle size={17} /><span>{notice}</span><button onClick={() => setNotice("")}><X size={15} /></button></div>}
          <div className="metric-grid">{cards.map(({ label, value, delta, icon: Icon, tone }) => <article className="metric-card" key={label}><div className={`metric-icon ${tone}`}><Icon size={20} /></div><small>{label}</small><strong>{value.toLocaleString("az-AZ")}</strong><p><Activity size={13} /> {delta}</p></article>)}</div>

          <article className="admin-panel report-panel" id="reports">
            <div className="panel-heading"><div><h2>Moderasiya növbəsi</h2><p>Şikayət səbəbləri və hesab metadata-sı; mesaj mətni görünmür</p></div><span className="queue-count">{reports.length} açıq</span></div>
            <div className="report-list">{reports.length === 0 && <p className="panel-empty">Açıq şikayət yoxdur.</p>}{reports.map((report) => <div className="report-item" key={report.id}><span className="report-icon"><Flag size={17} /></span><div className="report-copy"><b>@{report.reported?.username ?? "silinmiş_hesab"}</b><p>{report.reason}</p><small>@{report.reporter?.username ?? "naməlum"} · {relative(report.created_at)} · {report.status}</small></div><div className="report-actions">{report.status === "open" && <button title="Baxışa götür" onClick={() => resolveReport(report, "reviewing")}><Search size={15} /></button>}<button title="Həll et" className="resolve" onClick={() => resolveReport(report, "resolved")}><CheckCircle2 size={15} /></button><button title="Rədd et" className="dismiss" onClick={() => resolveReport(report, "dismissed")}><XCircle size={15} /></button></div></div>)}</div>
          </article>

          <div className="admin-grid-row">
            <article className="admin-panel activity-panel" id="audit"><div className="panel-heading"><div><h2>Audit hadisələri</h2><p>Məxfilik qorunmaqla sistem əməliyyatları</p></div><button className="text-button export-button" onClick={exportAudit}><Download size={14} /> CSV ixrac</button></div><div className="audit-list">{visibleLogs.length === 0 && <p className="panel-empty">Uyğun audit hadisəsi yoxdur.</p>}{visibleLogs.slice(0, 8).map((log, index) => <div className="audit-item" key={log.id}><span className={`audit-icon audit-${index % 4}`}>{index % 3 === 0 ? <CircleUserRound size={17} /> : index % 3 === 1 ? <MessageSquareText size={17} /> : <ShieldCheck size={17} />}</span><div><b>{actionLabels[log.action] ?? log.action}</b><small>{log.entity_type} · {log.entity_id?.slice(0, 8) ?? "sistem"}</small></div><time>{relative(log.created_at)}</time></div>)}</div></article>
            <article className="admin-panel health-panel" id="system"><div className="panel-heading"><div><h2>Sistem yoxlaması</h2><p>Son məlumat sorğusunun nəticəsi</p></div><Gauge size={20} /></div><div className="health-score"><div className={`score-ring ${healthy ? "" : "degraded"}`}><strong>{healthy ? "4/4" : "!"}</strong></div><p><b>{healthy ? "Bütün yoxlamalar keçdi" : "Diqqət tələb olunur"}</b><span>Son yenilənmə: indi</span></p></div><div className="service-list"><div><span><Database size={15} /> Məlumat bazası</span><b><i /> {healthy ? "İşləyir" : "Yoxla"}</b></div><div><span><Activity size={15} /> Mesaj kanalı</span><b><i /> {healthy ? "İşləyir" : "Yoxla"}</b></div><div><span><KeyRound size={15} /> Giriş xidməti</span><b><i /> İşləyir</b></div><div><span><LockKeyhole size={15} /> Şifrəli paketlər</span><b><i /> Aktiv</b></div></div></article>
          </div>

          <article className="admin-panel user-panel" id="users"><div className="panel-heading user-heading"><div><h2>İstifadəçilər</h2><p>Hesab statusu və moderasiya əməliyyatları</p></div><label className="duration-select">Dayandırma <select value={durationDays} onChange={(event) => setDurationDays(Number(event.target.value))}><option value={7}>7 gün</option><option value={30}>30 gün</option><option value={90}>90 gün</option><option value={365}>1 il</option></select></label><div className="table-search"><Search size={15} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Axtar" /></div></div><div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>İstifadəçi</th><th>Rol</th><th>Son aktivlik</th><th>Status</th><th aria-label="Əməliyyat" /></tr></thead><tbody>{visibleUsers.slice(0, 20).map((item) => <tr key={item.id}><td><span className="table-avatar">{item.display_name[0]}</span><div><b>{item.display_name}</b><small>@{item.username}</small></div></td><td><span className={`role-pill ${item.role}`}>{item.role}</span></td><td>{relative(item.last_seen)}</td><td><span className={item.suspended_until ? "status-pill suspended" : "status-pill active"}><i />{item.suspended_until ? "Dayandırılıb" : "Aktiv"}</span></td><td><button disabled={item.id === profile?.id} title={item.suspended_until ? "Bərpa et" : `${durationDays} gün dayandır`} className="icon-button" onClick={() => toggleSuspension(item)}>{item.suspended_until ? <CheckCircle2 size={17} /> : <Ban size={17} />}</button></td></tr>)}</tbody></table></div></article>
          <p className="admin-footer-note"><LockKeyhole size={13} /> Audit loglarında mesaj mətni, şəxsi açar və həssas profil məlumatı saxlanmır.</p>
        </div>
      </section>
    </main>
  );
}
