"use client";

import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  Ban,
  Bell,
  BellOff,
  CheckCheck,
  Copy,
  EllipsisVertical,
  Flag,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Menu,
  MessageCirclePlus,
  Pin,
  Search,
  SendHorizontal,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Timer,
  Trash2,
  UserRound,
  X,
} from "lucide-react";
import type { User } from "@supabase/supabase-js";
import Link from "next/link";
import { Brand } from "@/components/Brand";
import {
  checkTrustedDevice,
  decryptMessage,
  encryptMessage,
  encryptionLabel,
  ensureDeviceKeys,
  removeDeviceKeys,
  verifyDeviceRegistration,
  type DeviceKeyBundle,
  type EncryptedEnvelope,
  type PublishedDeviceKeys,
} from "@/lib/crypto";
import { supabase } from "@/lib/supabase";

type Profile = {
  id: string;
  username: string;
  display_name: string;
  bio: string;
  avatar_url: string | null;
  role: "user" | "moderator" | "admin";
  last_seen: string;
};

type Device = PublishedDeviceKeys & {
  user_id: string;
  name?: string;
  last_seen?: string;
  revoked_at?: string | null;
  key_version?: number;
};

type Conversation = {
  id: string;
  title: string | null;
  kind: "direct" | "group";
  updated_at: string;
  peer?: Profile;
  pinned?: boolean;
  disappearing_seconds?: number;
};

type DecryptedMessage = {
  id: string;
  sender_id: string;
  sender_device_id: string;
  text: string;
  created_at: string;
  expires_at: string | null;
  failed?: boolean;
  verified?: boolean;
  legacy?: boolean;
  deleted?: boolean;
};

type MessageRow = {
  id: string;
  sender_id: string;
  sender_device_id: string;
  client_nonce: string;
  algorithm: string;
  created_at: string;
  expires_at: string | null;
  deleted_at: string | null;
  message_envelopes: (EncryptedEnvelope & { recipient_device_id: string })[];
};

const expiryOptions = [
  { value: 0, label: "Söndürülüb" },
  { value: 3600, label: "1 saat" },
  { value: 86400, label: "24 saat" },
  { value: 604800, label: "7 gün" },
  { value: 2592000, label: "30 gün" },
];

function initials(name?: string) {
  return (name || "?").split(" ").map((part) => part[0]).join("").slice(0, 2).toUpperCase();
}

function time(value: string) {
  return new Intl.DateTimeFormat("az-AZ", { hour: "2-digit", minute: "2-digit" }).format(new Date(value));
}

function friendlyError(error: unknown) {
  const raw = error instanceof Error ? error.message : String(error ?? "");
  const messages: Record<string, string> = {
    account_suspended: "Hesab müvəqqəti dayandırılıb.",
    conversation_blocked: "Bu söhbətdə mesajlaşma bloklanıb.",
    delete_window_expired: "Mesajı hər kəs üçün silmə vaxtı bitib.",
    invalid_signature: "Mesajın rəqəmsal imzası düzgün deyil.",
    context_mismatch: "Mesajın təhlükəsizlik məlumatı uyğun gəlmir.",
    device_revoked: "Bu cihazın şifrələmə girişi ləğv edilib.",
    device_limit_reached: "Aktiv cihaz limiti dolub. Köhnə cihazlardan birini ləğv et.",
    message_rate_limit: "Çox sürətli mesaj göndərilir. Bir dəqiqə gözlə.",
    conversation_rate_limit: "Qısa müddətdə çox söhbət yaradılıb. Daha sonra yenidən yoxla.",
    report_rate_limit: "Şikayət limiti dolub. Daha sonra yenidən yoxla.",
    duplicate_report: "Bu şikayət artıq moderasiya növbəsindədir.",
  };
  const match = Object.keys(messages).find((key) => raw.includes(key));
  if (match) return messages[match];
  if (raw.includes("schema cache") || raw.includes("relation") || raw.includes("column")) {
    return "Məlumat bazası yenilənməyib. Təhlükəsizlik miqrasiyasını tətbiq et.";
  }
  return raw || "Əməliyyat tamamlanmadı.";
}

export function MessengerApp() {
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [device, setDevice] = useState<Device | null>(null);
  const [keys, setKeys] = useState<DeviceKeyBundle | null>(null);
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [messages, setMessages] = useState<DecryptedMessage[]>([]);
  const [peerDevices, setPeerDevices] = useState<Device[]>([]);
  const [ownDevices, setOwnDevices] = useState<Device[]>([]);
  const [draft, setDraft] = useState("");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [notice, setNotice] = useState("");
  const [showNewChat, setShowNewChat] = useState(false);
  const [showSecurity, setShowSecurity] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showReport, setShowReport] = useState(false);
  const [showMore, setShowMore] = useState(false);
  const [mobileSidebar, setMobileSidebar] = useState(true);
  const [blocked, setBlocked] = useState(false);
  const [notifications, setNotifications] = useState(false);
  const [disappearingSeconds, setDisappearingSeconds] = useState(0);
  const endRef = useRef<HTMLDivElement>(null);
  const previousMessageCount = useRef(0);

  const selected = conversations.find((item) => item.id === selectedId) ?? null;
  const filtered = useMemo(
    () => conversations
      .filter((item) => (item.peer?.display_name ?? item.title ?? "").toLowerCase().includes(search.toLowerCase()))
      .sort((a, b) => Number(Boolean(b.pinned)) - Number(Boolean(a.pinned)) || +new Date(b.updated_at) - +new Date(a.updated_at)),
    [conversations, search],
  );

  const bootstrap = useCallback(async (account: User) => {
    setLoading(true);
    setNotice("");
    try {
      const { data: profileData, error: profileError } = await supabase
        .from("profiles")
        .select("id,username,display_name,bio,avatar_url,role,last_seen")
        .eq("id", account.id)
        .single();
      if (profileError) throw profileError;
      setProfile(profileData as Profile);

      const keyBundle = await ensureDeviceKeys(account.id);
      setKeys(keyBundle);
      const deviceName = /Mobi|Android/i.test(navigator.userAgent) ? "Mobil brauzer" : "Veb brauzer";
      const { data: deviceData, error: deviceError } = await supabase
        .from("devices")
        .upsert(
          {
            user_id: account.id,
            name: deviceName,
            public_key: keyBundle.publicKey,
            signing_public_key: keyBundle.signingPublicKey,
            key_signature: keyBundle.keySignature,
            key_version: 2,
            fingerprint: keyBundle.fingerprint,
            last_seen: new Date().toISOString(),
          },
          { onConflict: "user_id,fingerprint" },
        )
        .select("id,user_id,name,last_seen,revoked_at,public_key,signing_public_key,key_signature,key_version,fingerprint")
        .single();
      if (deviceError) throw deviceError;
      if (deviceData.revoked_at) throw new Error("device_revoked");
      setDevice(deviceData as Device);
      await supabase.from("profiles").update({ last_seen: new Date().toISOString() }).eq("id", account.id);
      setNotifications(localStorage.getItem("privchat:notifications") === "on");
    } catch (error) {
      setNotice(friendlyError(error));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadOwnDevices = useCallback(async (accountId: string) => {
    const { data, error } = await supabase
      .from("devices")
      .select("id,user_id,name,last_seen,revoked_at,public_key,signing_public_key,key_signature,key_version,fingerprint")
      .eq("user_id", accountId)
      .order("last_seen", { ascending: false });
    if (error) throw error;
    setOwnDevices((data ?? []) as Device[]);
  }, []);

  const loadConversations = useCallback(async (accountId: string) => {
    const { data, error } = await supabase
      .from("conversation_members")
      .select("conversation_id, conversations!inner(id,title,kind,updated_at)")
      .eq("user_id", accountId)
      .order("joined_at", { ascending: false });
    if (error) throw error;
    const membershipRows = (data ?? []) as unknown as { conversation_id: string; conversations: Conversation }[];
    const base = membershipRows.map((row) => row.conversations);
    if (!base.length) {
      setConversations([]);
      return;
    }
    const ids = base.map((item) => item.id);
    const [{ data: members }, { data: preferences }] = await Promise.all([
      supabase
        .from("conversation_members")
        .select("conversation_id,user_id,profiles!inner(id,username,display_name,bio,avatar_url,role,last_seen)")
        .in("conversation_id", ids)
        .neq("user_id", accountId),
      supabase
        .from("conversation_preferences")
        .select("conversation_id,pinned,disappearing_seconds")
        .eq("user_id", accountId)
        .in("conversation_id", ids),
    ]);
    const memberRows = (members ?? []) as unknown as { conversation_id: string; profiles: Profile }[];
    const preferenceRows = (preferences ?? []) as unknown as { conversation_id: string; pinned: boolean; disappearing_seconds: number }[];
    const peers = new Map(memberRows.map((row) => [row.conversation_id, row.profiles]));
    const preferenceMap = new Map(preferenceRows.map((row) => [row.conversation_id, row]));
    const ready = base.map((item) => ({
      ...item,
      peer: peers.get(item.id),
      pinned: Boolean(preferenceMap.get(item.id)?.pinned),
      disappearing_seconds: Number(preferenceMap.get(item.id)?.disappearing_seconds ?? 0),
    }));
    setConversations(ready);
    setSelectedId((current) => current ?? ready[0]?.id ?? null);
  }, []);

  const loadMessages = useCallback(async (conversationId: string) => {
    if (!user || !device || !keys) return;
    const [{ data: rows, error }, { data: deviceRows }] = await Promise.all([
      supabase
        .from("encrypted_messages")
        .select("id,sender_id,sender_device_id,client_nonce,algorithm,created_at,expires_at,deleted_at,message_envelopes(recipient_device_id,ciphertext,iv,salt,ephemeral_public_key,signature,aad,algorithm)")
        .eq("conversation_id", conversationId)
        .or(`expires_at.is.null,expires_at.gt.${new Date().toISOString()}`)
        .order("created_at", { ascending: true })
        .limit(200),
      supabase
        .from("devices")
        .select("id,user_id,public_key,signing_public_key,key_signature,key_version,fingerprint")
        .is("revoked_at", null),
    ]);
    if (error) throw error;
    const availableDevices = (deviceRows ?? []) as unknown as Device[];
    const messageRows = (rows ?? []) as unknown as MessageRow[];
    const deviceMap = new Map(availableDevices.map((row) => [row.id, row]));
    const decoded = await Promise.all(messageRows.map(async (row): Promise<DecryptedMessage> => {
      if (row.deleted_at) return { ...row, text: "Mesaj silindi.", deleted: true };
      try {
        const envelopes = row.message_envelopes as (EncryptedEnvelope & { recipient_device_id: string })[];
        let envelope = envelopes.find((item) => item.recipient_device_id === device.id);
        let agreementDevice = deviceMap.get(row.sender_device_id);

        // V1 messages were not copied to the sender's own device. Keep them readable during migration.
        if (!envelope && row.sender_id === user.id) {
          envelope = envelopes[0];
          agreementDevice = envelope ? deviceMap.get(envelope.recipient_device_id) : undefined;
        }
        if (!envelope || !agreementDevice) throw new Error("missing_key");

        if (envelope.ephemeral_public_key) {
          const senderDevice = deviceMap.get(row.sender_device_id);
          if (!senderDevice) throw new Error("missing_sender_key");
          const trust = await checkTrustedDevice(senderDevice);
          if (trust === "changed") throw new Error("device_key_changed");
          if (trust === "invalid") throw new Error("invalid_device_registration");
          agreementDevice = senderDevice;
        }

        const result = await decryptMessage(
          envelope,
          keys.privateKey,
          agreementDevice.public_key,
          agreementDevice.signing_public_key,
          {
            conversationId,
            senderId: row.sender_id,
            senderDeviceId: row.sender_device_id,
            recipientDeviceId: envelope.recipient_device_id,
            nonce: row.client_nonce,
          },
        );
        return { ...row, text: result.plaintext, verified: result.verified, legacy: result.legacy };
      } catch (decodeError) {
        const keyChanged = String(decodeError).includes("device_key_changed");
        return {
          ...row,
          text: keyChanged ? "Cihaz açarı dəyişib. Təhlükəsizlik kodunu yenidən yoxla." : "Bu mesaj təhlükəsiz şəkildə açıla bilmədi.",
          failed: true,
        };
      }
    }));
    setMessages(decoded);

    const unread = messageRows.filter((row) => row.sender_id !== user.id && !row.deleted_at).map((row) => ({
      message_id: row.id,
      user_id: user.id,
      delivered_at: new Date().toISOString(),
      read_at: new Date().toISOString(),
    }));
    if (unread.length) await supabase.from("message_receipts").upsert(unread, { onConflict: "message_id,user_id" });

    if (
      notifications && document.hidden && decoded.length > previousMessageCount.current &&
      "Notification" in window && Notification.permission === "granted"
    ) {
      new Notification("PrivChat", { body: "Yeni şifrəli mesajın var.", icon: "/icons/icon-192.png" });
    }
    previousMessageCount.current = decoded.length;
    requestAnimationFrame(() => endRef.current?.scrollIntoView({ behavior: "smooth" }));
  }, [device, keys, notifications, user]);

  const loadConversationControls = useCallback(async (conversation: Conversation, accountId: string) => {
    const peerId = conversation.peer?.id;
    const [{ data: preferences }, { data: blocks }, { data: devices }] = await Promise.all([
      supabase.from("conversation_preferences").select("pinned,disappearing_seconds").eq("conversation_id", conversation.id).eq("user_id", accountId).maybeSingle(),
      peerId ? supabase.from("blocks").select("blocked_id").eq("blocker_id", accountId).eq("blocked_id", peerId).maybeSingle() : Promise.resolve({ data: null }),
      peerId ? supabase.from("devices").select("id,user_id,public_key,signing_public_key,key_signature,key_version,fingerprint").eq("user_id", peerId).is("revoked_at", null) : Promise.resolve({ data: [] }),
    ]);
    setDisappearingSeconds(Number(preferences?.disappearing_seconds ?? 0));
    setBlocked(Boolean(blocks));
    setPeerDevices((devices ?? []) as Device[]);
  }, []);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      const account = data.session?.user ?? null;
      setUser(account);
      if (account) bootstrap(account);
      else setLoading(false);
    });
    const { data: listener } = supabase.auth.onAuthStateChange((_event, session) => setUser(session?.user ?? null));
    return () => listener.subscription.unsubscribe();
  }, [bootstrap]);

  useEffect(() => {
    if (!user || !device) return;
    // Data loading is the subscription boundary for the signed-in account.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadConversations(user.id).catch((error) => setNotice(friendlyError(error)));
  }, [device, loadConversations, user]);

  useEffect(() => {
    if (!selected || !user) return;
    // Drafts are intentionally device-local and restored when a conversation changes.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setDraft(localStorage.getItem(`privchat:draft:${selected.id}`) ?? "");
    previousMessageCount.current = 0;
    loadConversationControls(selected, user.id).catch((error) => setNotice(friendlyError(error)));
  }, [loadConversationControls, selected, user]);

  useEffect(() => {
    if (!selectedId) return;
    if (draft) localStorage.setItem(`privchat:draft:${selectedId}`, draft);
    else localStorage.removeItem(`privchat:draft:${selectedId}`);
  }, [draft, selectedId]);

  useEffect(() => {
    if (!selectedId || !device || !keys) return;
    // Initial fetch is paired with the realtime subscription below.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadMessages(selectedId).catch((error) => setNotice(friendlyError(error)));
    const channel = supabase
      .channel(`messages:${selectedId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "encrypted_messages", filter: `conversation_id=eq.${selectedId}` }, () => loadMessages(selectedId))
      .subscribe();
    return () => { supabase.removeChannel(channel); };
  }, [device, keys, loadMessages, selectedId]);

  async function sendMessage(event: FormEvent) {
    event.preventDefault();
    const text = draft.trim();
    if (!text || !selected || !device || !keys || !user || sending || blocked) return;
    setSending(true);
    setNotice("");
    try {
      const { data: members, error: memberError } = await supabase
        .from("conversation_members")
        .select("user_id")
        .eq("conversation_id", selected.id);
      if (memberError) throw memberError;
      const memberIds = ((members ?? []) as unknown as { user_id: string }[]).map((row) => row.user_id);
      const { data: targetRows, error: deviceError } = await supabase
        .from("devices")
        .select("id,user_id,public_key,signing_public_key,key_signature,key_version,fingerprint")
        .in("user_id", memberIds)
        .is("revoked_at", null);
      if (deviceError) throw deviceError;

      const validation = await Promise.all((targetRows ?? []).map(async (target: Device) => ({
        target,
        valid: await verifyDeviceRegistration(target),
      })));
      const targets = validation.filter((entry) => entry.valid).map((entry) => entry.target);
      if (!targets.some((target) => target.id === device.id)) throw new Error("Cari cihazın açarı təsdiqlənmədi.");
      if (!targets.some((target) => target.user_id !== user.id)) {
        throw new Error("Dostun yeni təhlükəsizlik açarını yaratmaq üçün tətbiqi bir dəfə açmalıdır.");
      }

      const clientNonce = crypto.randomUUID();
      const envelopes = await Promise.all(targets.map(async (target) => ({
        recipient_device_id: target.id,
        ...(await encryptMessage(text, keys.signingPrivateKey, target.public_key, {
          conversationId: selected.id,
          senderId: user.id,
          senderDeviceId: device.id,
          recipientDeviceId: target.id,
          nonce: clientNonce,
        })),
      })));
      const { error: sendError } = await supabase.rpc("send_encrypted_message", {
        target_conversation: selected.id,
        source_device: device.id,
        envelopes,
        client_nonce: clientNonce,
        expires_in_seconds: disappearingSeconds,
        message_kind: "text",
      });
      if (sendError) throw sendError;
      setDraft("");
      await Promise.all([loadMessages(selected.id), loadConversations(user.id)]);
    } catch (error) {
      setNotice(friendlyError(error));
    } finally {
      setSending(false);
    }
  }

  async function createChat(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!user) return;
    const username = String(new FormData(event.currentTarget).get("username") ?? "").trim().toLowerCase().replace(/^@/, "");
    setNotice("");
    const { data: peer, error } = await supabase.from("profiles").select("id").eq("username", username).maybeSingle();
    if (error || !peer) { setNotice("Bu istifadəçi adı tapılmadı."); return; }
    const { data: conversationId, error: createError } = await supabase.rpc("create_direct_conversation", { peer_id: peer.id });
    if (createError) { setNotice(friendlyError(createError)); return; }
    await loadConversations(user.id);
    setSelectedId(conversationId);
    setMobileSidebar(false);
    setShowNewChat(false);
  }

  async function savePreference(changes: { pinned?: boolean; disappearing_seconds?: number }) {
    if (!selected || !user) return;
    const next = {
      conversation_id: selected.id,
      user_id: user.id,
      pinned: changes.pinned ?? Boolean(selected.pinned),
      disappearing_seconds: changes.disappearing_seconds ?? disappearingSeconds,
    };
    const { error } = await supabase.from("conversation_preferences").upsert(next, { onConflict: "conversation_id,user_id" });
    if (error) { setNotice(friendlyError(error)); return; }
    setDisappearingSeconds(next.disappearing_seconds);
    await loadConversations(user.id);
  }

  async function toggleBlock() {
    if (!selected?.peer) return;
    const { error } = await supabase.rpc("toggle_block", { target_user: selected.peer.id, should_block: !blocked, block_reason: "" });
    if (error) setNotice(friendlyError(error));
    else { setBlocked(!blocked); setShowMore(false); }
  }

  async function submitReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected?.peer || !user) return;
    const reason = String(new FormData(event.currentTarget).get("reason") ?? "").trim();
    const { error } = await supabase.rpc("submit_report", {
      target_user: selected.peer.id,
      target_conversation: selected.id,
      report_reason: reason,
    });
    if (error) setNotice(friendlyError(error));
    else { setNotice("Şikayət təhlükəsiz şəkildə moderasiya növbəsinə əlavə edildi."); setShowReport(false); }
  }

  async function deleteMessage(messageId: string) {
    const { error } = await supabase.rpc("delete_message_for_everyone", { target_message: messageId });
    if (error) setNotice(friendlyError(error));
    else if (selected) await loadMessages(selected.id);
  }

  async function saveProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!user) return;
    const form = new FormData(event.currentTarget);
    const updates = {
      display_name: String(form.get("display_name") ?? "").trim(),
      bio: String(form.get("bio") ?? "").trim(),
    };
    const { data, error } = await supabase
      .from("profiles")
      .update(updates)
      .eq("id", user.id)
      .select("id,username,display_name,bio,avatar_url,role,last_seen")
      .single();
    if (error) setNotice(friendlyError(error));
    else { setProfile(data as Profile); setShowSettings(false); }
  }

  async function toggleNotifications() {
    if (!notifications && "Notification" in window) {
      const permission = await Notification.requestPermission();
      if (permission !== "granted") { setNotice("Bildiriş icazəsi verilmədi."); return; }
    }
    const next = !notifications;
    setNotifications(next);
    localStorage.setItem("privchat:notifications", next ? "on" : "off");
  }

  async function revokeDevice(target: Device) {
    if (!user) return;
    const isCurrent = target.id === device?.id;
    const confirmed = window.confirm(
      isCurrent
        ? "Bu cihazın şifrələmə açarı silinəcək və hesabdan çıxış ediləcək. Davam edilsin?"
        : `${target.name ?? "Cihaz"} üçün mesaj girişi ləğv edilsin?`,
    );
    if (!confirmed) return;
    const { error } = await supabase.rpc("revoke_device", { target_device: target.id });
    if (error) { setNotice(friendlyError(error)); return; }
    if (isCurrent) {
      await removeDeviceKeys(user.id);
      await supabase.auth.signOut();
      return;
    }
    await loadOwnDevices(user.id);
    setNotice("Cihazın şifrələmə girişi ləğv edildi.");
  }

  const emptyState = !loading && conversations.length === 0;

  if (!loading && !user) {
    return (
      <main className="gate-screen"><div className="gate-card">
        <div className="auth-orb"><LockKeyhole size={30} /></div><Brand />
        <h1>Şəxsi söhbətlərinə daxil ol</h1><p>Mesajların açılması üçün əvvəlcə hesabına giriş etməlisən.</p>
        <Link className="button button-primary large" href="/">Giriş səhifəsinə qayıt</Link>
      </div></main>
    );
  }

  return (
    <main className="messenger-shell">
      <aside className={`messenger-sidebar ${mobileSidebar ? "mobile-open" : ""}`}>
        <div className="messenger-brand-row"><Brand compact /><button className="icon-button" onClick={() => setShowNewChat(true)} aria-label="Yeni söhbət"><MessageCirclePlus size={19} /></button></div>
        <div className="search-box"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Söhbətlərdə axtar" /></div>
        <div className="conversation-heading"><span>Mesajlar</span><small>{conversations.length}</small></div>
        <div className="conversation-list">
          {loading && <div className="sidebar-loader"><LoaderCircle className="spin" size={22} /> Təhlükəsiz açar hazırlanır...</div>}
          {emptyState && <button className="empty-conversations" onClick={() => setShowNewChat(true)}><MessageCirclePlus size={25} /><b>İlk söhbətini başlat</b><span>İstifadəçi adı ilə dostunu tap.</span></button>}
          {filtered.map((conversation, index) => (
            <button key={conversation.id} className={`conversation-item ${selectedId === conversation.id ? "active" : ""}`} onClick={() => { setSelectedId(conversation.id); setMobileSidebar(false); }}>
              <span className={`avatar avatar-${index % 5}`}>{initials(conversation.peer?.display_name ?? conversation.title ?? "S")}</span>
              <span className="conversation-copy"><b>{conversation.peer?.display_name ?? conversation.title ?? "Şifrəli söhbət"}</b><small><LockKeyhole size={11} /> Şifrəli mesajlar</small></span>
              <span className="conversation-meta">{conversation.pinned && <Pin size={10} />}<time>{time(conversation.updated_at)}</time></span>
            </button>
          ))}
        </div>
        <div className="sidebar-profile">
          <span className="avatar avatar-self">{initials(profile?.display_name)}</span><div><b>{profile?.display_name ?? "Yüklənir"}</b><small>@{profile?.username ?? "..."}</small></div>
          <button className="icon-button" onClick={() => { setShowSettings(true); if (user) loadOwnDevices(user.id).catch((error) => setNotice(friendlyError(error))); }} aria-label="Ayarlar"><Settings size={18} /></button>
          <button className="icon-button" onClick={() => supabase.auth.signOut()} aria-label="Çıxış"><LogOut size={18} /></button>
        </div>
      </aside>

      <section className={`chat-panel ${mobileSidebar ? "mobile-hidden" : ""}`}>
        {selected ? <>
          <header className="chat-header">
            <button className="icon-button mobile-only" onClick={() => setMobileSidebar(true)} aria-label="Söhbətlər"><ArrowLeft size={20} /></button>
            <span className="avatar avatar-1">{initials(selected.peer?.display_name ?? selected.title ?? "S")}</span>
            <div className="chat-person"><b>{selected.peer?.display_name ?? selected.title ?? "Şifrəli söhbət"}</b><small><i /> {selected.peer ? `son aktivlik ${time(selected.peer.last_seen)}` : "təhlükəsiz qrup"}</small></div>
            <div className="chat-header-actions">
              <button className={`icon-button ${selected.pinned ? "active-control" : ""}`} onClick={() => savePreference({ pinned: !selected.pinned })} aria-label="Söhbəti sabitlə"><Pin size={18} /></button>
              <button className="icon-button" onClick={() => setShowSecurity(true)} aria-label="Təhlükəsizlik"><ShieldCheck size={19} /></button>
              <div className="more-menu-wrap"><button className="icon-button" onClick={() => setShowMore((value) => !value)} aria-label="Daha çox"><EllipsisVertical size={19} /></button>
                {showMore && <div className="chat-more-menu"><button onClick={() => { setShowReport(true); setShowMore(false); }}><Flag size={15} /> Şikayət et</button><button className="danger" onClick={toggleBlock}><Ban size={15} /> {blocked ? "Bloku aç" : "İstifadəçini blokla"}</button></div>}
              </div>
            </div>
          </header>
          <div className="chat-security-bar"><LockKeyhole size={12} /> İmzalanmış, ucdan-uca şifrəli paketlər. <button onClick={() => setShowSecurity(true)}>Yoxla</button></div>
          <div className="message-scroller">
            <div className="day-divider"><span>Bu gün</span></div>
            {messages.length === 0 && <div className="chat-empty"><span><ShieldCheck size={27} /></span><h3>Aranızda təhlükəsiz xətt hazırdır</h3><p>İlk mesajı göndər. Yalnız sizin təsdiqlənmiş cihazlarınız onu aça bilər.</p></div>}
            {messages.map((message) => {
              const mine = message.sender_id === user?.id;
              const canDelete = mine && !message.deleted;
              return <div className={`message-row ${mine ? "mine" : "theirs"}`} key={message.id}><div className={`message-bubble ${message.failed ? "failed" : ""} ${message.deleted ? "deleted" : ""}`}>
                <p>{message.text}</p><time>
                  {message.expires_at && <Timer size={11} />}{message.verified && <ShieldCheck size={11} />}{message.legacy && <ShieldAlert size={11} />} {time(message.created_at)} {mine && <CheckCheck size={13} />}
                  {canDelete && <button onClick={() => deleteMessage(message.id)} title="Hər kəs üçün sil"><Trash2 size={11} /></button>}
                </time>
              </div></div>;
            })}
            <div ref={endRef} />
          </div>
          {notice && <div className="chat-notice"><span>{notice}</span><button onClick={() => setNotice("")}><X size={15} /></button></div>}
          {blocked ? <div className="blocked-composer"><Ban size={16} /> Bu istifadəçini bloklamısan. Mesaj göndərmək bağlıdır.</div> :
            <form className="message-composer" onSubmit={sendMessage}><input value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Şifrəli mesaj yaz..." maxLength={5000} /><span className="composer-count">{draft.length}/5000</span><button className="send-button" disabled={!draft.trim() || sending} aria-label="Göndər">{sending ? <LoaderCircle className="spin" size={19} /> : <SendHorizontal size={19} />}</button></form>}
        </> : <div className="no-chat-selected"><button className="icon-button mobile-only no-chat-menu" onClick={() => setMobileSidebar(true)}><Menu size={20} /></button><span><MessageCirclePlus size={32} /></span><h2>Söhbət seç</h2><p>Mesajlaşmaq üçün soldan bir söhbət seç və ya yenisini yarat.</p></div>}
      </section>

      {showNewChat && <div className="small-modal-backdrop"><form className="small-modal" onSubmit={createChat}><button type="button" className="icon-button modal-close" onClick={() => setShowNewChat(false)}><X size={18} /></button><span className="small-modal-icon"><UserRound size={24} /></span><p className="eyebrow">Yeni söhbət</p><h2>Dostunu tap</h2><p>PrivChat istifadəçi adını daxil et.</p><label><span>İstifadəçi adı</span><div className="username-field"><b>@</b><input name="username" required placeholder="aylin_7" /></div></label><button className="button button-primary">Təhlükəsiz söhbət yarat</button></form></div>}

      {showSecurity && <div className="security-drawer-backdrop"><aside className="security-drawer"><button className="icon-button drawer-close" onClick={() => setShowSecurity(false)}><X size={19} /></button><span className="drawer-shield"><ShieldCheck size={29} /></span><p className="eyebrow">Təhlükəsiz söhbət</p><h2>Cihaz kodlarını yoxla</h2><p>Kodları dostunla başqa təhlükəsiz kanalda müqayisə et. Cihaz açarı dəyişərsə, mesaj açılmadan xəbərdarlıq göstərilir.</p><div className="fingerprint-label">Sənin bu cihazın</div><div className="fingerprint-code">{device?.fingerprint ?? "AÇAR HAZIRLANIR"}</div><button className="button button-ghost" onClick={() => navigator.clipboard.writeText(device?.fingerprint ?? "")}><Copy size={17} /> Kodu kopyala</button>
        <div className="peer-fingerprints"><b>{selected?.peer?.display_name ?? "Dostun"} · {peerDevices.length} cihaz</b>{peerDevices.map((item) => <code key={item.id}>{item.fingerprint}</code>)}</div>
        <label className="expiry-control"><span><Timer size={15} /> Yoxa çıxan mesajlar</span><select value={disappearingSeconds} onChange={(event) => savePreference({ disappearing_seconds: Number(event.target.value) })}>{expiryOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label>
        <div className="drawer-facts"><div><LockKeyhole size={17} /><span><b>AES‑256‑GCM</b><small>Hər paket üçün yeni açar</small></span></div><div><ShieldCheck size={17} /><span><b>{encryptionLabel()}</b><small>İmza və açar razılaşması</small></span></div></div>
      </aside></div>}

      {showSettings && <div className="small-modal-backdrop"><form className="small-modal settings-modal" onSubmit={saveProfile}><button type="button" className="icon-button modal-close" onClick={() => setShowSettings(false)}><X size={18} /></button><span className="small-modal-icon"><Settings size={24} /></span><p className="eyebrow">Hesab ayarları</p><h2>Profil və məxfilik</h2><label><span>Görünən ad</span><input name="display_name" defaultValue={profile?.display_name} minLength={1} maxLength={50} required /></label><label><span>Bio</span><textarea name="bio" defaultValue={profile?.bio} maxLength={160} placeholder="Özün haqqında qısa məlumat" /></label><button type="button" className="notification-setting" onClick={toggleNotifications}>{notifications ? <Bell size={17} /> : <BellOff size={17} />}<span><b>Məxfi bildirişlər</b><small>Mesaj mətni bildirişdə göstərilmir</small></span><i className={notifications ? "on" : ""} /></button><div className="device-manager"><div className="device-manager-title"><Smartphone size={16} /><span><b>Cihazlar</b><small>Tanımadığın cihazın girişini ləğv et</small></span></div>{ownDevices.map((item) => <div className={`managed-device ${item.revoked_at ? "revoked" : ""}`} key={item.id}><span><b>{item.name ?? "Veb brauzer"}{item.id === device?.id ? " · bu cihaz" : ""}</b><small>{item.revoked_at ? "Giriş ləğv edilib" : item.last_seen ? `Son aktivlik: ${time(item.last_seen)}` : "Aktiv"}</small></span>{!item.revoked_at && <button type="button" onClick={() => revokeDevice(item)}>Ləğv et</button>}</div>)}</div><button className="button button-primary">Dəyişiklikləri saxla</button></form></div>}

      {showReport && <div className="small-modal-backdrop"><form className="small-modal" onSubmit={submitReport}><button type="button" className="icon-button modal-close" onClick={() => setShowReport(false)}><X size={18} /></button><span className="small-modal-icon warning-icon"><Flag size={24} /></span><p className="eyebrow">Moderasiya</p><h2>Şikayət göndər</h2><p>Admin mesajların açıq mətnini görə bilməz. Problemi qısa və aydın təsvir et.</p><label><span>Səbəb</span><textarea name="reason" minLength={3} maxLength={500} required placeholder="Nə baş verdiyini yaz..." /></label><button className="button button-primary">Moderasiya növbəsinə göndər</button></form></div>}
    </main>
  );
}
