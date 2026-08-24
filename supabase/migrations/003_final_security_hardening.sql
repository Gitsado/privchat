-- Final least-privilege pass. Apply after 002_security_and_controls.sql.

create or replace function public.is_conversation_member(
  target_conversation uuid,
  target_user uuid default auth.uid()
)
returns boolean
language sql stable security definer set search_path = public
as $$
  select target_user = auth.uid() and exists (
    select 1 from public.conversation_members
    where conversation_id = target_conversation and user_id = target_user
  );
$$;

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
  if not public.is_account_active(peer_id) then raise exception 'peer_not_available'; end if;
  if exists (
    select 1 from public.blocks
    where (blocker_id = current_user and blocked_id = peer_id)
       or (blocker_id = peer_id and blocked_id = current_user)
  ) then raise exception 'conversation_blocked'; end if;

  select c.id into existing_id
  from public.conversations c
  where c.kind = 'direct'
    and (select count(*) from public.conversation_members cm where cm.conversation_id = c.id) = 2
    and exists (select 1 from public.conversation_members cm where cm.conversation_id = c.id and cm.user_id = current_user)
    and exists (select 1 from public.conversation_members cm where cm.conversation_id = c.id and cm.user_id = peer_id)
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

create or replace function public.protect_profile_privileges()
returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if not public.is_admin(auth.uid()) then
    new.role := old.role;
    new.is_verified := old.is_verified;
  end if;
  if not public.is_admin(auth.uid())
     and coalesce(current_setting('privchat.moderation_action', true), '') <> '1' then
    new.suspended_until := old.suspended_until;
  end if;
  return new;
end;
$$;

create or replace function public.admin_set_suspension(
  target_user uuid,
  suspend boolean,
  duration_days integer default 30
)
returns void
language plpgsql security definer set search_path = public
as $$
declare
  caller_role public.account_role;
  target_role public.account_role;
begin
  select role into caller_role from public.profiles where id = auth.uid();
  select role into target_role from public.profiles where id = target_user;
  if caller_role not in ('admin', 'moderator') then raise exception 'forbidden'; end if;
  if target_role is null then raise exception 'user_not_found'; end if;
  if target_user = auth.uid() then raise exception 'cannot_suspend_self'; end if;
  if caller_role = 'moderator' and target_role <> 'user' then raise exception 'insufficient_role'; end if;

  perform set_config('privchat.moderation_action', '1', true);
  update public.profiles
  set suspended_until = case
    when suspend then now() + make_interval(days => least(greatest(duration_days, 1), 365))
    else null
  end
  where id = target_user;
  insert into public.audit_logs(actor_id, action, entity_type, entity_id, metadata)
  values (
    auth.uid(), case when suspend then 'user.suspended' else 'user.unsuspended' end,
    'profile', target_user::text,
    jsonb_build_object('duration_days', least(greatest(duration_days, 1), 365))
  );
end;
$$;

create or replace function public.protect_device_status()
returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if new.user_id <> old.user_id then raise exception 'device_owner_immutable'; end if;
  if coalesce(current_setting('privchat.device_revoke_action', true), '') <> '1' then
    new.revoked_at := old.revoked_at;
  end if;
  return new;
end;
$$;

drop trigger if exists devices_protect_status on public.devices;
create trigger devices_protect_status before update on public.devices
for each row execute function public.protect_device_status();

create or replace function public.limit_active_devices()
returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if (select count(*) from public.devices where user_id = new.user_id and revoked_at is null) >= 10 then
    raise exception 'device_limit_reached';
  end if;
  return new;
end;
$$;

drop trigger if exists devices_limit_active on public.devices;
create trigger devices_limit_active before insert on public.devices
for each row execute function public.limit_active_devices();

create or replace function public.revoke_device(target_device uuid)
returns void
language plpgsql security definer set search_path = public
as $$
begin
  if auth.uid() is null then raise exception 'unauthenticated'; end if;
  if not exists (select 1 from public.devices where id = target_device and user_id = auth.uid()) then
    raise exception 'device_not_found';
  end if;
  perform set_config('privchat.device_revoke_action', '1', true);
  update public.devices set revoked_at = coalesce(revoked_at, now()) where id = target_device;
  insert into public.audit_logs(actor_id, action, entity_type, entity_id)
  values (auth.uid(), 'device.revoked', 'device', target_device::text);
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
  expected_algorithm constant text := 'ECDH-P256-EPHEMERAL/HKDF-SHA256/AES-256-GCM+ECDSA-P256';
begin
  if current_user is null or not public.is_conversation_member(target_conversation) then raise exception 'not_a_member'; end if;
  if not public.is_account_active(current_user) then raise exception 'account_suspended'; end if;
  if client_nonce is null then raise exception 'missing_nonce'; end if;
  if message_kind <> 'text' then raise exception 'invalid_message_kind'; end if;
  if not exists (
    select 1 from public.devices
    where id = source_device and user_id = current_user and revoked_at is null
      and signing_public_key is not null and coalesce(key_signature, '') <> ''
  ) then raise exception 'invalid_device'; end if;
  if jsonb_typeof(envelopes) <> 'array'
     or jsonb_array_length(envelopes) < 2
     or jsonb_array_length(envelopes) > 64 then
    raise exception 'invalid_envelope_count';
  end if;
  if exists (
    select 1 from public.blocks b
    where (b.blocker_id = current_user and exists (
      select 1 from public.conversation_members cm where cm.conversation_id = target_conversation and cm.user_id = b.blocked_id
    )) or (b.blocked_id = current_user and exists (
      select 1 from public.conversation_members cm where cm.conversation_id = target_conversation and cm.user_id = b.blocker_id
    ))
  ) then raise exception 'conversation_blocked'; end if;

  for envelope in select value from jsonb_array_elements(envelopes)
  loop
    if jsonb_typeof(envelope) <> 'object'
       or coalesce(envelope ->> 'algorithm', '') <> expected_algorithm
       or jsonb_typeof(envelope -> 'ephemeral_public_key') <> 'object'
       or char_length(coalesce(envelope ->> 'ciphertext', '')) not between 1 and 30000
       or char_length(coalesce(envelope ->> 'iv', '')) not between 16 and 64
       or char_length(coalesce(envelope ->> 'salt', '')) not between 16 and 128
       or char_length(coalesce(envelope ->> 'signature', '')) not between 32 and 512
       or char_length(coalesce(envelope ->> 'aad', '')) not between 20 and 1024 then
      raise exception 'invalid_envelope';
    end if;
    if not exists (
      select 1 from public.devices d
      join public.conversation_members cm on cm.user_id = d.user_id
      where d.id = (envelope ->> 'recipient_device_id')::uuid
        and cm.conversation_id = target_conversation
        and d.revoked_at is null
        and d.signing_public_key is not null
        and coalesce(d.key_signature, '') <> ''
    ) then raise exception 'invalid_recipient_device'; end if;
  end loop;

  if exists (
    select 1 from public.conversation_members cm
    where cm.conversation_id = target_conversation
      and not exists (
        select 1
        from jsonb_array_elements(envelopes) e
        join public.devices d on d.id = (e ->> 'recipient_device_id')::uuid
        where d.user_id = cm.user_id and d.revoked_at is null
      )
  ) then raise exception 'missing_participant_envelope'; end if;

  insert into public.encrypted_messages(
    conversation_id, sender_id, sender_device_id, client_nonce, kind, algorithm, expires_at
  ) values (
    target_conversation, current_user, source_device, client_nonce, message_kind, expected_algorithm,
    case when expires_in_seconds > 0
      then now() + make_interval(secs => least(expires_in_seconds, 2592000))
      else null end
  ) returning id into new_message;

  for envelope in select value from jsonb_array_elements(envelopes)
  loop
    insert into public.message_envelopes(
      message_id, recipient_device_id, ciphertext, iv, salt,
      ephemeral_public_key, signature, aad, algorithm
    ) values (
      new_message, (envelope ->> 'recipient_device_id')::uuid,
      envelope ->> 'ciphertext', envelope ->> 'iv', envelope ->> 'salt',
      envelope -> 'ephemeral_public_key', envelope ->> 'signature', envelope ->> 'aad', expected_algorithm
    );
  end loop;

  update public.conversations set updated_at = now() where id = target_conversation;
  insert into public.audit_logs(actor_id, action, entity_type, entity_id, metadata)
  values (current_user, 'message.sent', 'message', new_message::text, jsonb_build_object('conversation_id', target_conversation));
  return new_message;
end;
$$;

drop policy if exists "users register own devices" on public.devices;
create policy "users register own devices" on public.devices
for insert to authenticated
with check (user_id = auth.uid() and public.is_account_active());

drop policy if exists "users update own devices" on public.devices;
create policy "users update own devices" on public.devices
for update to authenticated
using (user_id = auth.uid() and public.is_account_active())
with check (user_id = auth.uid() and public.is_account_active());

drop policy if exists "users update own profile" on public.profiles;
create policy "users update own profile" on public.profiles
for update to authenticated
using (id = auth.uid() and public.is_account_active())
with check (id = auth.uid() and public.is_account_active());

drop policy if exists "users write own receipts" on public.message_receipts;
create policy "users write own receipts" on public.message_receipts
for insert to authenticated with check (
  user_id = auth.uid() and public.is_account_active()
  and exists (
    select 1 from public.encrypted_messages m
    where m.id = message_id and public.is_conversation_member(m.conversation_id)
  )
);

drop policy if exists "users update own receipts" on public.message_receipts;
create policy "users update own receipts" on public.message_receipts
for update to authenticated
using (user_id = auth.uid() and public.is_account_active())
with check (user_id = auth.uid() and public.is_account_active());

drop policy if exists "users create reports" on public.reports;
create policy "users create reports" on public.reports
for insert to authenticated with check (
  reporter_id = auth.uid()
  and public.is_account_active()
  and reported_user_id is distinct from auth.uid()
  and (conversation_id is null or public.is_conversation_member(conversation_id))
);

revoke all on all tables in schema public from anon;
revoke insert, update, delete on public.audit_logs from authenticated;
revoke insert, update, delete on public.encrypted_messages from authenticated;
revoke insert, update, delete on public.message_envelopes from authenticated;

revoke all on function public.is_conversation_member(uuid, uuid) from public, anon;
revoke all on function public.create_direct_conversation(uuid) from public, anon;
revoke all on function public.send_encrypted_message(uuid, uuid, jsonb, uuid, integer, text) from public, anon;
revoke all on function public.toggle_block(uuid, boolean, text) from public, anon;
revoke all on function public.delete_message_for_everyone(uuid) from public, anon;
revoke all on function public.get_admin_metrics() from public, anon;
revoke all on function public.admin_set_suspension(uuid, boolean, integer) from public, anon;
revoke all on function public.admin_resolve_report(uuid, public.report_status, text) from public, anon;
revoke all on function public.revoke_device(uuid) from public, anon;

grant execute on function public.is_conversation_member(uuid, uuid) to authenticated;
grant execute on function public.create_direct_conversation(uuid) to authenticated;
grant execute on function public.send_encrypted_message(uuid, uuid, jsonb, uuid, integer, text) to authenticated;
grant execute on function public.toggle_block(uuid, boolean, text) to authenticated;
grant execute on function public.delete_message_for_everyone(uuid) to authenticated;
grant execute on function public.get_admin_metrics() to authenticated;
grant execute on function public.admin_set_suspension(uuid, boolean, integer) to authenticated;
grant execute on function public.admin_resolve_report(uuid, public.report_status, text) to authenticated;
grant execute on function public.revoke_device(uuid) to authenticated;
