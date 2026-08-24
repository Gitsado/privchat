-- PrivChat security hardening and user/admin controls.
-- Run this once on databases created with the first schema version.

alter table public.devices add column if not exists signing_public_key jsonb;
alter table public.devices add column if not exists key_signature text;
alter table public.devices add column if not exists key_version integer not null default 2;

alter table public.encrypted_messages add column if not exists client_nonce uuid;
update public.encrypted_messages set client_nonce = gen_random_uuid() where client_nonce is null;
alter table public.encrypted_messages alter column client_nonce set not null;
alter table public.encrypted_messages alter column algorithm set default 'ECDH-P256-EPHEMERAL/HKDF-SHA256/AES-256-GCM+ECDSA-P256';

do $$ begin
  alter table public.encrypted_messages add constraint encrypted_messages_device_nonce_key unique (sender_device_id, client_nonce);
exception when duplicate_object then null;
end $$;

alter table public.message_envelopes add column if not exists ephemeral_public_key jsonb;
alter table public.message_envelopes add column if not exists signature text;
alter table public.message_envelopes add column if not exists aad text;
alter table public.message_envelopes add column if not exists algorithm text not null default 'ECDH-P256-EPHEMERAL/HKDF-SHA256/AES-256-GCM+ECDSA-P256';

alter table public.reports add column if not exists resolution_note text not null default '';

create table if not exists public.blocks (
  blocker_id uuid not null references public.profiles(id) on delete cascade,
  blocked_id uuid not null references public.profiles(id) on delete cascade,
  reason text not null default '' check (char_length(reason) <= 160),
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  check (blocker_id <> blocked_id)
);

create table if not exists public.conversation_preferences (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  pinned boolean not null default false,
  archived boolean not null default false,
  muted_until timestamptz,
  disappearing_seconds integer not null default 0 check (disappearing_seconds between 0 and 2592000),
  updated_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);

create index if not exists blocks_blocked_idx on public.blocks(blocked_id, created_at desc);
create index if not exists preferences_user_idx on public.conversation_preferences(user_id, pinned desc, updated_at desc);

drop trigger if exists preferences_touch on public.conversation_preferences;
create trigger preferences_touch before update on public.conversation_preferences
for each row execute function public.touch_updated_at();

create or replace function public.is_account_active(target_user uuid default auth.uid())
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (select 1 from public.profiles where id = target_user and (suspended_until is null or suspended_until < now()));
$$;

create or replace function public.is_admin(target_user uuid default auth.uid())
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (select 1 from public.profiles where id=target_user and role='admin');
$$;

create or replace function public.is_staff(target_user uuid default auth.uid())
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (select 1 from public.profiles where id=target_user and role in ('admin','moderator'));
$$;

create or replace function public.create_direct_conversation(peer_id uuid)
returns uuid language plpgsql security definer set search_path = public
as $$
declare current_user uuid := auth.uid(); existing_id uuid; new_id uuid;
begin
  if current_user is null or peer_id = current_user then raise exception 'invalid_peer'; end if;
  if not public.is_account_active(current_user) then raise exception 'account_suspended'; end if;
  if not public.is_account_active(peer_id) then raise exception 'peer_not_available'; end if;
  if exists (select 1 from public.blocks where (blocker_id=current_user and blocked_id=peer_id) or (blocker_id=peer_id and blocked_id=current_user)) then
    raise exception 'conversation_blocked';
  end if;
  select c.id into existing_id from public.conversations c
  where c.kind='direct'
    and (select count(*) from public.conversation_members cm where cm.conversation_id=c.id)=2
    and public.is_conversation_member(c.id,current_user) and public.is_conversation_member(c.id,peer_id)
  limit 1;
  if existing_id is not null then return existing_id; end if;
  insert into public.conversations(kind,created_by) values ('direct',current_user) returning id into new_id;
  insert into public.conversation_members(conversation_id,user_id,role)
  values (new_id,current_user,'owner'),(new_id,peer_id,'member');
  insert into public.audit_logs(actor_id,action,entity_type,entity_id,metadata)
  values (current_user,'conversation.created','conversation',new_id::text,jsonb_build_object('kind','direct'));
  return new_id;
end;
$$;

drop function if exists public.send_encrypted_message(uuid, uuid, jsonb, text);
create or replace function public.send_encrypted_message(
  target_conversation uuid, source_device uuid, envelopes jsonb, client_nonce uuid,
  expires_in_seconds integer default 0, message_kind text default 'text'
) returns uuid language plpgsql security definer set search_path = public
as $$
declare current_user uuid := auth.uid(); new_message uuid; envelope jsonb;
begin
  if current_user is null or not public.is_conversation_member(target_conversation,current_user) then raise exception 'not_a_member'; end if;
  if not public.is_account_active(current_user) then raise exception 'account_suspended'; end if;
  if not exists (select 1 from public.devices where id=source_device and user_id=current_user and revoked_at is null) then raise exception 'invalid_device'; end if;
  if jsonb_array_length(envelopes)<1 then raise exception 'missing_envelope'; end if;
  if exists (
    select 1 from public.blocks b where
      (b.blocker_id=current_user and exists (select 1 from public.conversation_members cm where cm.conversation_id=target_conversation and cm.user_id=b.blocked_id))
      or (b.blocked_id=current_user and exists (select 1 from public.conversation_members cm where cm.conversation_id=target_conversation and cm.user_id=b.blocker_id))
  ) then raise exception 'conversation_blocked'; end if;
  insert into public.encrypted_messages(conversation_id,sender_id,sender_device_id,client_nonce,kind,algorithm,expires_at)
  values (
    target_conversation,current_user,source_device,client_nonce,message_kind,
    coalesce(envelopes->0->>'algorithm','ECDH-P256-EPHEMERAL/HKDF-SHA256/AES-256-GCM+ECDSA-P256'),
    case when expires_in_seconds>0 then now()+make_interval(secs=>least(expires_in_seconds,2592000)) else null end
  ) returning id into new_message;
  for envelope in select * from jsonb_array_elements(envelopes) loop
    if not exists (
      select 1 from public.devices d join public.conversation_members cm on cm.user_id=d.user_id
      where d.id=(envelope->>'recipient_device_id')::uuid and cm.conversation_id=target_conversation and d.revoked_at is null
    ) then raise exception 'invalid_recipient_device'; end if;
    insert into public.message_envelopes(
      message_id,recipient_device_id,ciphertext,iv,salt,ephemeral_public_key,signature,aad,algorithm
    ) values (
      new_message,(envelope->>'recipient_device_id')::uuid,envelope->>'ciphertext',envelope->>'iv',envelope->>'salt',
      envelope->'ephemeral_public_key',envelope->>'signature',envelope->>'aad',
      coalesce(envelope->>'algorithm','ECDH-P256/HKDF-SHA256/AES-256-GCM')
    );
  end loop;
  update public.conversations set updated_at=now() where id=target_conversation;
  insert into public.audit_logs(actor_id,action,entity_type,entity_id,metadata)
  values (current_user,'message.sent','message',new_message::text,jsonb_build_object('conversation_id',target_conversation));
  return new_message;
end;
$$;

create or replace function public.toggle_block(target_user uuid, should_block boolean, block_reason text default '')
returns void language plpgsql security definer set search_path = public
as $$
begin
  if auth.uid() is null or target_user=auth.uid() then raise exception 'invalid_target'; end if;
  if should_block then
    insert into public.blocks(blocker_id,blocked_id,reason) values (auth.uid(),target_user,left(coalesce(block_reason,''),160))
    on conflict (blocker_id,blocked_id) do update set reason=excluded.reason,created_at=now();
  else delete from public.blocks where blocker_id=auth.uid() and blocked_id=target_user;
  end if;
  insert into public.audit_logs(actor_id,action,entity_type,entity_id)
  values (auth.uid(),case when should_block then 'user.blocked' else 'user.unblocked' end,'profile',target_user::text);
end;
$$;

create or replace function public.delete_message_for_everyone(target_message uuid)
returns void language plpgsql security definer set search_path = public
as $$
begin
  if not exists (select 1 from public.encrypted_messages where id=target_message and sender_id=auth.uid() and created_at>now()-interval '15 minutes' and deleted_at is null) then
    raise exception 'delete_window_expired';
  end if;
  update public.encrypted_messages set deleted_at=now() where id=target_message;
  delete from public.message_envelopes where message_id=target_message;
  insert into public.audit_logs(actor_id,action,entity_type,entity_id) values (auth.uid(),'message.deleted','message',target_message::text);
end;
$$;

create or replace function public.get_admin_metrics()
returns jsonb language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_staff() then raise exception 'forbidden'; end if;
  return jsonb_build_object(
    'users',(select count(*) from public.profiles),
    'active_today',(select count(*) from public.profiles where last_seen>now()-interval '24 hours'),
    'messages_today',(select count(*) from public.encrypted_messages where created_at>date_trunc('day',now())),
    'open_reports',(select count(*) from public.reports where status in ('open','reviewing')),
    'devices',(select count(*) from public.devices where revoked_at is null),
    'verified_devices',(select count(*) from public.devices where revoked_at is null and coalesce(key_signature,'')<>''),
    'blocks',(select count(*) from public.blocks)
  );
end;
$$;

drop function if exists public.admin_set_suspension(uuid, boolean);
create or replace function public.admin_set_suspension(target_user uuid, suspend boolean, duration_days integer default 30)
returns void language plpgsql security definer set search_path = public
as $$
begin
  if not public.is_staff() then raise exception 'forbidden'; end if;
  if target_user=auth.uid() then raise exception 'cannot_suspend_self'; end if;
  update public.profiles set suspended_until=case when suspend then now()+make_interval(days=>least(greatest(duration_days,1),365)) else null end where id=target_user;
  insert into public.audit_logs(actor_id,action,entity_type,entity_id,metadata)
  values (auth.uid(),case when suspend then 'user.suspended' else 'user.unsuspended' end,'profile',target_user::text,jsonb_build_object('duration_days',duration_days));
end;
$$;

create or replace function public.admin_resolve_report(target_report uuid, new_status public.report_status, note text default '')
returns void language plpgsql security definer set search_path = public
as $$
begin
  if not public.is_staff() then raise exception 'forbidden'; end if;
  if new_status not in ('reviewing','resolved','dismissed') then raise exception 'invalid_status'; end if;
  update public.reports set status=new_status,assigned_to=auth.uid(),resolution_note=left(coalesce(note,''),500),
    resolved_at=case when new_status in ('resolved','dismissed') then now() else null end where id=target_report;
  insert into public.audit_logs(actor_id,action,entity_type,entity_id,metadata)
  values (auth.uid(),'report.'||new_status::text,'report',target_report::text,jsonb_build_object('status',new_status));
end;
$$;

alter table public.blocks enable row level security;
alter table public.conversation_preferences enable row level security;
drop policy if exists "users read own blocks" on public.blocks;
create policy "users read own blocks" on public.blocks for select to authenticated using (blocker_id=auth.uid());
drop policy if exists "users manage own blocks" on public.blocks;
drop policy if exists "members read own preferences" on public.conversation_preferences;
create policy "members read own preferences" on public.conversation_preferences for select to authenticated using (user_id=auth.uid() and public.is_conversation_member(conversation_id));
drop policy if exists "members insert own preferences" on public.conversation_preferences;
create policy "members insert own preferences" on public.conversation_preferences for insert to authenticated with check (user_id=auth.uid() and public.is_conversation_member(conversation_id));
drop policy if exists "members update own preferences" on public.conversation_preferences;
create policy "members update own preferences" on public.conversation_preferences for update to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid() and public.is_conversation_member(conversation_id));

drop policy if exists "reporter or admins read reports" on public.reports;
create policy "reporter or admins read reports" on public.reports for select to authenticated using (reporter_id=auth.uid() or public.is_staff());
drop policy if exists "admins update reports" on public.reports;
create policy "admins update reports" on public.reports for update to authenticated using (public.is_staff()) with check (public.is_staff());
drop policy if exists "admins read audit logs" on public.audit_logs;
create policy "admins read audit logs" on public.audit_logs for select to authenticated using (public.is_staff());

grant execute on function public.send_encrypted_message(uuid,uuid,jsonb,uuid,integer,text) to authenticated;
grant execute on function public.toggle_block(uuid,boolean,text) to authenticated;
grant execute on function public.delete_message_for_everyone(uuid) to authenticated;
grant execute on function public.admin_set_suspension(uuid,boolean,integer) to authenticated;
grant execute on function public.admin_resolve_report(uuid,public.report_status,text) to authenticated;
