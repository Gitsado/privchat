-- PrivChat / Supabase schema
-- Run this entire file once in Supabase Dashboard -> SQL Editor.

create extension if not exists pgcrypto;

create type public.account_role as enum ('user', 'moderator', 'admin');
create type public.conversation_kind as enum ('direct', 'group');
create type public.member_role as enum ('member', 'admin', 'owner');
create type public.report_status as enum ('open', 'reviewing', 'resolved', 'dismissed');

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (username ~ '^[a-z0-9_]{3,24}$'),
  display_name text not null check (char_length(display_name) between 1 and 50),
  bio text not null default '' check (char_length(bio) <= 160),
  avatar_url text,
  role public.account_role not null default 'user',
  is_verified boolean not null default false,
  suspended_until timestamptz,
  last_seen timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  name text not null default 'Web cihazı' check (char_length(name) <= 80),
  public_key jsonb not null,
  signing_public_key jsonb not null,
  key_signature text not null,
  key_version integer not null default 2 check (key_version >= 1),
  fingerprint text not null,
  last_seen timestamptz not null default now(),
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  unique (user_id, fingerprint)
);

create table public.conversations (
  id uuid primary key default gen_random_uuid(),
  kind public.conversation_kind not null default 'direct',
  title text check (char_length(title) <= 80),
  created_by uuid not null references public.profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  role public.member_role not null default 'member',
  muted_until timestamptz,
  joined_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);

create table public.encrypted_messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references public.profiles(id),
  sender_device_id uuid not null references public.devices(id),
  client_nonce uuid not null,
  kind text not null default 'text' check (kind in ('text', 'system')),
  reply_to uuid references public.encrypted_messages(id) on delete set null,
  algorithm text not null default 'ECDH-P256-EPHEMERAL/HKDF-SHA256/AES-256-GCM+ECDSA-P256',
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  edited_at timestamptz,
  deleted_at timestamptz,
  unique (sender_device_id, client_nonce)
);

create table public.message_envelopes (
  message_id uuid not null references public.encrypted_messages(id) on delete cascade,
  recipient_device_id uuid not null references public.devices(id) on delete cascade,
  ciphertext text not null,
  iv text not null,
  salt text not null,
  ephemeral_public_key jsonb,
  signature text,
  aad text,
  algorithm text not null default 'ECDH-P256-EPHEMERAL/HKDF-SHA256/AES-256-GCM+ECDSA-P256',
  created_at timestamptz not null default now(),
  primary key (message_id, recipient_device_id)
);

create table public.message_receipts (
  message_id uuid not null references public.encrypted_messages(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  delivered_at timestamptz default now(),
  read_at timestamptz,
  primary key (message_id, user_id)
);

create table public.blocks (
  blocker_id uuid not null references public.profiles(id) on delete cascade,
  blocked_id uuid not null references public.profiles(id) on delete cascade,
  reason text not null default '' check (char_length(reason) <= 160),
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  check (blocker_id <> blocked_id)
);

create table public.conversation_preferences (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  pinned boolean not null default false,
  archived boolean not null default false,
  muted_until timestamptz,
  disappearing_seconds integer not null default 0 check (disappearing_seconds between 0 and 2592000),
  updated_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references public.profiles(id),
  reported_user_id uuid references public.profiles(id),
  conversation_id uuid references public.conversations(id) on delete set null,
  reason text not null check (char_length(reason) between 3 and 500),
  status public.report_status not null default 'open',
  assigned_to uuid references public.profiles(id),
  resolution_note text not null default '' check (char_length(resolution_note) <= 500),
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);

create table public.audit_logs (
  id bigint generated always as identity primary key,
  actor_id uuid references public.profiles(id) on delete set null,
  action text not null,
  entity_type text not null,
  entity_id text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index conversation_members_user_idx on public.conversation_members(user_id, joined_at desc);
create index encrypted_messages_conversation_idx on public.encrypted_messages(conversation_id, created_at desc);
create index message_envelopes_recipient_idx on public.message_envelopes(recipient_device_id);
create index audit_logs_created_idx on public.audit_logs(created_at desc);
create index reports_status_idx on public.reports(status, created_at desc);
create index blocks_blocked_idx on public.blocks(blocked_id, created_at desc);
create index preferences_user_idx on public.conversation_preferences(user_id, pinned desc, updated_at desc);

create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger profiles_touch before update on public.profiles
for each row execute function public.touch_updated_at();
create trigger conversations_touch before update on public.conversations
for each row execute function public.touch_updated_at();
create trigger preferences_touch before update on public.conversation_preferences
for each row execute function public.touch_updated_at();

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare
  requested_username text;
  safe_username text;
begin
  requested_username := lower(coalesce(new.raw_user_meta_data ->> 'username', split_part(new.email, '@', 1)));
  safe_username := regexp_replace(requested_username, '[^a-z0-9_]', '', 'g');
  if char_length(safe_username) < 3 then safe_username := 'user_' || substr(new.id::text, 1, 8); end if;
  if exists (select 1 from public.profiles where username = safe_username) then
    safe_username := left(safe_username, 15) || '_' || substr(new.id::text, 1, 8);
  end if;
  insert into public.profiles (id, username, display_name)
  values (
    new.id,
    safe_username,
    left(coalesce(nullif(new.raw_user_meta_data ->> 'display_name', ''), safe_username), 50)
  );
  insert into public.audit_logs (actor_id, action, entity_type, entity_id)
  values (new.id, 'account.created', 'profile', new.id::text);
  return new;
end;
$$;

create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

create or replace function public.is_conversation_member(target_conversation uuid, target_user uuid default auth.uid())
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists (
    select 1 from public.conversation_members
    where conversation_id = target_conversation and user_id = target_user
  );
$$;

create or replace function public.is_admin(target_user uuid default auth.uid())
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = target_user and role = 'admin'
  );
$$;

create or replace function public.is_staff(target_user uuid default auth.uid())
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = target_user and role in ('admin', 'moderator')
  );
$$;

create or replace function public.is_account_active(target_user uuid default auth.uid())
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = target_user and (suspended_until is null or suspended_until < now())
  );
$$;

create or replace function public.protect_profile_privileges()
returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if not public.is_admin(auth.uid()) then
    new.role := old.role;
    new.is_verified := old.is_verified;
    new.suspended_until := old.suspended_until;
  end if;
  return new;
end;
$$;

create trigger profiles_protect_privileges before update on public.profiles
for each row execute function public.protect_profile_privileges();

create or replace function public.create_direct_conversation(peer_id uuid)
returns uuid
language plpgsql security definer set search_path = public
as $$
declare
  current_user uuid := auth.uid();
  existing_id uuid;
  new_id uuid;
begin
  if current_user is null or peer_id = current_user then raise exception 'invalid_peer'; end if;
  if not public.is_account_active(current_user) then raise exception 'account_suspended'; end if;
  if not exists (select 1 from public.profiles where id = peer_id and (suspended_until is null or suspended_until < now())) then
    raise exception 'peer_not_available';
  end if;
  if exists (
    select 1 from public.blocks
    where (blocker_id = current_user and blocked_id = peer_id)
       or (blocker_id = peer_id and blocked_id = current_user)
  ) then raise exception 'conversation_blocked'; end if;
  select c.id into existing_id
  from public.conversations c
  where c.kind = 'direct'
    and (select count(*) from public.conversation_members cm where cm.conversation_id = c.id) = 2
    and public.is_conversation_member(c.id, current_user)
    and public.is_conversation_member(c.id, peer_id)
  limit 1;
  if existing_id is not null then return existing_id; end if;

  insert into public.conversations(kind, created_by) values ('direct', current_user) returning id into new_id;
  insert into public.conversation_members(conversation_id, user_id, role)
  values (new_id, current_user, 'owner'), (new_id, peer_id, 'member');
  insert into public.audit_logs(actor_id, action, entity_type, entity_id, metadata)
  values (current_user, 'conversation.created', 'conversation', new_id::text, jsonb_build_object('kind', 'direct'));
  return new_id;
end;
$$;

create or replace function public.send_encrypted_message(
  target_conversation uuid,
  source_device uuid,
  envelopes jsonb,
  client_nonce uuid,
  expires_in_seconds integer default 0,
  message_kind text default 'text'
)
returns uuid
language plpgsql security definer set search_path = public
as $$
declare
  current_user uuid := auth.uid();
  new_message uuid;
  envelope jsonb;
begin
  if current_user is null or not public.is_conversation_member(target_conversation, current_user) then
    raise exception 'not_a_member';
  end if;
  if not public.is_account_active(current_user) then raise exception 'account_suspended'; end if;
  if not exists (select 1 from public.devices where id = source_device and user_id = current_user and revoked_at is null) then
    raise exception 'invalid_device';
  end if;
  if jsonb_array_length(envelopes) < 1 then raise exception 'missing_envelope'; end if;
  if exists (
    select 1 from public.blocks b
    where (b.blocker_id = current_user and exists (
      select 1 from public.conversation_members cm where cm.conversation_id = target_conversation and cm.user_id = b.blocked_id
    )) or (b.blocked_id = current_user and exists (
      select 1 from public.conversation_members cm where cm.conversation_id = target_conversation and cm.user_id = b.blocker_id
    ))
  ) then raise exception 'conversation_blocked'; end if;

  insert into public.encrypted_messages(
    conversation_id, sender_id, sender_device_id, client_nonce, kind, algorithm, expires_at
  ) values (
    target_conversation,
    current_user,
    source_device,
    client_nonce,
    message_kind,
    coalesce(envelopes -> 0 ->> 'algorithm', 'ECDH-P256-EPHEMERAL/HKDF-SHA256/AES-256-GCM+ECDSA-P256'),
    case when expires_in_seconds > 0 then now() + make_interval(secs => least(expires_in_seconds, 2592000)) else null end
  )
  returning id into new_message;

  for envelope in select * from jsonb_array_elements(envelopes)
  loop
    if not exists (
      select 1 from public.devices d
      join public.conversation_members cm on cm.user_id = d.user_id
      where d.id = (envelope ->> 'recipient_device_id')::uuid
        and cm.conversation_id = target_conversation
        and d.revoked_at is null
    ) then raise exception 'invalid_recipient_device'; end if;
    insert into public.message_envelopes(
      message_id, recipient_device_id, ciphertext, iv, salt,
      ephemeral_public_key, signature, aad, algorithm
    )
    values (
      new_message,
      (envelope ->> 'recipient_device_id')::uuid,
      envelope ->> 'ciphertext',
      envelope ->> 'iv',
      envelope ->> 'salt',
      envelope -> 'ephemeral_public_key',
      envelope ->> 'signature',
      envelope ->> 'aad',
      coalesce(envelope ->> 'algorithm', 'ECDH-P256/HKDF-SHA256/AES-256-GCM')
    );
  end loop;

  update public.conversations set updated_at = now() where id = target_conversation;
  insert into public.audit_logs(actor_id, action, entity_type, entity_id, metadata)
  values (current_user, 'message.sent', 'message', new_message::text, jsonb_build_object('conversation_id', target_conversation));
  return new_message;
end;
$$;

create or replace function public.toggle_block(target_user uuid, should_block boolean, block_reason text default '')
returns void
language plpgsql security definer set search_path = public
as $$
begin
  if auth.uid() is null or target_user = auth.uid() then raise exception 'invalid_target'; end if;
  if should_block then
    insert into public.blocks(blocker_id, blocked_id, reason)
    values (auth.uid(), target_user, left(coalesce(block_reason, ''), 160))
    on conflict (blocker_id, blocked_id) do update set reason = excluded.reason, created_at = now();
  else
    delete from public.blocks where blocker_id = auth.uid() and blocked_id = target_user;
  end if;
  insert into public.audit_logs(actor_id, action, entity_type, entity_id)
  values (auth.uid(), case when should_block then 'user.blocked' else 'user.unblocked' end, 'profile', target_user::text);
end;
$$;

create or replace function public.delete_message_for_everyone(target_message uuid)
returns void
language plpgsql security definer set search_path = public
as $$
begin
  if not exists (
    select 1 from public.encrypted_messages
    where id = target_message and sender_id = auth.uid() and created_at > now() - interval '15 minutes' and deleted_at is null
  ) then raise exception 'delete_window_expired'; end if;
  update public.encrypted_messages set deleted_at = now() where id = target_message;
  delete from public.message_envelopes where message_id = target_message;
  insert into public.audit_logs(actor_id, action, entity_type, entity_id)
  values (auth.uid(), 'message.deleted', 'message', target_message::text);
end;
$$;

create or replace function public.get_admin_metrics()
returns jsonb
language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_staff() then raise exception 'forbidden'; end if;
  return jsonb_build_object(
    'users', (select count(*) from public.profiles),
    'active_today', (select count(*) from public.profiles where last_seen > now() - interval '24 hours'),
    'messages_today', (select count(*) from public.encrypted_messages where created_at > date_trunc('day', now())),
    'open_reports', (select count(*) from public.reports where status in ('open', 'reviewing')),
    'devices', (select count(*) from public.devices where revoked_at is null),
    'verified_devices', (select count(*) from public.devices where revoked_at is null and key_signature <> ''),
    'blocks', (select count(*) from public.blocks)
  );
end;
$$;

create or replace function public.admin_set_suspension(target_user uuid, suspend boolean, duration_days integer default 30)
returns void
language plpgsql security definer set search_path = public
as $$
begin
  if not public.is_staff() then raise exception 'forbidden'; end if;
  if target_user = auth.uid() then raise exception 'cannot_suspend_self'; end if;
  update public.profiles set suspended_until = case when suspend then now() + make_interval(days => least(greatest(duration_days, 1), 365)) else null end
  where id = target_user;
  insert into public.audit_logs(actor_id, action, entity_type, entity_id, metadata)
  values (
    auth.uid(), case when suspend then 'user.suspended' else 'user.unsuspended' end,
    'profile', target_user::text, jsonb_build_object('duration_days', duration_days)
  );
end;
$$;

create or replace function public.admin_resolve_report(target_report uuid, new_status public.report_status, note text default '')
returns void
language plpgsql security definer set search_path = public
as $$
begin
  if not public.is_staff() then raise exception 'forbidden'; end if;
  if new_status not in ('reviewing', 'resolved', 'dismissed') then raise exception 'invalid_status'; end if;
  update public.reports
  set status = new_status,
      assigned_to = auth.uid(),
      resolution_note = left(coalesce(note, ''), 500),
      resolved_at = case when new_status in ('resolved', 'dismissed') then now() else null end
  where id = target_report;
  insert into public.audit_logs(actor_id, action, entity_type, entity_id, metadata)
  values (auth.uid(), 'report.' || new_status::text, 'report', target_report::text, jsonb_build_object('status', new_status));
end;
$$;

alter table public.profiles enable row level security;
alter table public.devices enable row level security;
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.encrypted_messages enable row level security;
alter table public.message_envelopes enable row level security;
alter table public.message_receipts enable row level security;
alter table public.blocks enable row level security;
alter table public.conversation_preferences enable row level security;
alter table public.reports enable row level security;
alter table public.audit_logs enable row level security;

create policy "authenticated profiles are discoverable" on public.profiles
for select to authenticated using (true);
create policy "users update own profile" on public.profiles
for update to authenticated using (id = auth.uid()) with check (id = auth.uid());
create policy "admins update profiles" on public.profiles
for update to authenticated using (public.is_admin()) with check (public.is_admin());

create policy "active public device keys are discoverable" on public.devices
for select to authenticated using (revoked_at is null or user_id = auth.uid());
create policy "users register own devices" on public.devices
for insert to authenticated with check (user_id = auth.uid());
create policy "users update own devices" on public.devices
for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy "members read conversations" on public.conversations
for select to authenticated using (public.is_conversation_member(id));
create policy "members read membership" on public.conversation_members
for select to authenticated using (public.is_conversation_member(conversation_id));

create policy "members read message metadata" on public.encrypted_messages
for select to authenticated using (public.is_conversation_member(conversation_id));
create policy "participants read their encrypted envelopes" on public.message_envelopes
for select to authenticated using (
  exists (select 1 from public.devices d where d.id = recipient_device_id and d.user_id = auth.uid())
  or exists (select 1 from public.encrypted_messages m where m.id = message_id and m.sender_id = auth.uid())
);

create policy "members read receipts" on public.message_receipts
for select to authenticated using (
  exists (select 1 from public.encrypted_messages m where m.id = message_id and public.is_conversation_member(m.conversation_id))
);
create policy "users write own receipts" on public.message_receipts
for insert to authenticated with check (user_id = auth.uid());
create policy "users update own receipts" on public.message_receipts
for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy "users read own blocks" on public.blocks
for select to authenticated using (blocker_id = auth.uid());
create policy "members read own preferences" on public.conversation_preferences
for select to authenticated using (user_id = auth.uid() and public.is_conversation_member(conversation_id));
create policy "members insert own preferences" on public.conversation_preferences
for insert to authenticated with check (user_id = auth.uid() and public.is_conversation_member(conversation_id));
create policy "members update own preferences" on public.conversation_preferences
for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid() and public.is_conversation_member(conversation_id));

create policy "users create reports" on public.reports
for insert to authenticated with check (reporter_id = auth.uid());
create policy "reporter or admins read reports" on public.reports
for select to authenticated using (reporter_id = auth.uid() or public.is_staff());
create policy "admins update reports" on public.reports
for update to authenticated using (public.is_staff()) with check (public.is_staff());

create policy "admins read audit logs" on public.audit_logs
for select to authenticated using (public.is_staff());

grant execute on function public.create_direct_conversation(uuid) to authenticated;
grant execute on function public.send_encrypted_message(uuid, uuid, jsonb, uuid, integer, text) to authenticated;
grant execute on function public.toggle_block(uuid, boolean, text) to authenticated;
grant execute on function public.delete_message_for_everyone(uuid) to authenticated;
grant execute on function public.get_admin_metrics() to authenticated;
grant execute on function public.admin_set_suspension(uuid, boolean, integer) to authenticated;
grant execute on function public.admin_resolve_report(uuid, public.report_status, text) to authenticated;

alter publication supabase_realtime add table public.encrypted_messages;
alter publication supabase_realtime add table public.message_receipts;

-- After your own account is created, promote it once:
-- update public.profiles set role = 'admin' where username = 'YOUR_USERNAME';

-- After this base schema, apply migrations/003_final_security_hardening.sql,
-- then migrations/004_abuse_and_privilege_hardening.sql.
