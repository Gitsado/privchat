-- Abuse controls, strict function privileges, and retention helpers.
-- Apply after 003_final_security_hardening.sql.

create index if not exists encrypted_messages_sender_created_idx
on public.encrypted_messages(sender_id, created_at desc);
create index if not exists conversations_creator_created_idx
on public.conversations(created_by, created_at desc);
create index if not exists reports_reporter_created_idx
on public.reports(reporter_id, created_at desc);
create index if not exists audit_logs_actor_created_idx
on public.audit_logs(actor_id, created_at desc);

create or replace function public.limit_message_rate()
returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if new.sender_id is distinct from auth.uid() then raise exception 'invalid_sender'; end if;
  if (select count(*) from public.encrypted_messages where sender_id = new.sender_id and created_at > now() - interval '1 minute') >= 60
     or (select count(*) from public.encrypted_messages where sender_id = new.sender_id and created_at > now() - interval '1 hour') >= 1000 then
    raise exception 'message_rate_limit';
  end if;
  return new;
end;
$$;

drop trigger if exists encrypted_messages_rate_limit on public.encrypted_messages;
create trigger encrypted_messages_rate_limit before insert on public.encrypted_messages
for each row execute function public.limit_message_rate();

create or replace function public.limit_conversation_rate()
returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if new.created_by is distinct from auth.uid() then raise exception 'invalid_creator'; end if;
  if (select count(*) from public.conversations where created_by = new.created_by and created_at > now() - interval '1 hour') >= 30 then
    raise exception 'conversation_rate_limit';
  end if;
  return new;
end;
$$;

drop trigger if exists conversations_rate_limit on public.conversations;
create trigger conversations_rate_limit before insert on public.conversations
for each row execute function public.limit_conversation_rate();

create or replace function public.submit_report(
  target_user uuid,
  target_conversation uuid,
  report_reason text
)
returns uuid
language plpgsql security definer set search_path = public
as $$
declare
  current_user uuid := auth.uid();
  clean_reason text := btrim(coalesce(report_reason, ''));
  new_report uuid;
begin
  if current_user is null then raise exception 'unauthenticated'; end if;
  if not public.is_account_active() then raise exception 'account_suspended'; end if;
  if target_user is null or target_user = current_user then raise exception 'invalid_target'; end if;
  if char_length(clean_reason) not between 3 and 500 then raise exception 'invalid_report_reason'; end if;
  if not exists (select 1 from public.profiles where id = target_user) then raise exception 'user_not_found'; end if;

  if target_conversation is not null and (
    not public.is_conversation_member(target_conversation)
    or not exists (
      select 1 from public.conversation_members
      where conversation_id = target_conversation and user_id = target_user
    )
  ) then raise exception 'invalid_report_context'; end if;

  if (select count(*) from public.reports where reporter_id = current_user and created_at > now() - interval '1 hour') >= 5 then
    raise exception 'report_rate_limit';
  end if;
  if exists (
    select 1 from public.reports
    where reporter_id = current_user
      and reported_user_id = target_user
      and conversation_id is not distinct from target_conversation
      and status in ('open', 'reviewing')
      and created_at > now() - interval '24 hours'
  ) then raise exception 'duplicate_report'; end if;

  insert into public.reports(reporter_id, reported_user_id, conversation_id, reason)
  values (current_user, target_user, target_conversation, clean_reason)
  returning id into new_report;
  insert into public.audit_logs(actor_id, action, entity_type, entity_id)
  values (current_user, 'report.created', 'report', new_report::text);
  return new_report;
end;
$$;

drop policy if exists "users create reports" on public.reports;
revoke insert on public.reports from authenticated;

drop policy if exists "members insert own preferences" on public.conversation_preferences;
create policy "members insert own preferences" on public.conversation_preferences
for insert to authenticated with check (
  user_id = auth.uid()
  and public.is_account_active()
  and public.is_conversation_member(conversation_id)
);

drop policy if exists "members update own preferences" on public.conversation_preferences;
create policy "members update own preferences" on public.conversation_preferences
for update to authenticated
using (user_id = auth.uid() and public.is_account_active())
with check (
  user_id = auth.uid()
  and public.is_account_active()
  and public.is_conversation_member(conversation_id)
);

create or replace function public.purge_expired_messages(batch_size integer default 1000)
returns integer
language plpgsql security definer set search_path = public
as $$
declare
  deleted_count integer;
begin
  with expired as (
    select id from public.encrypted_messages
    where expires_at is not null and expires_at <= now()
    order by expires_at
    limit least(greatest(coalesce(batch_size, 1000), 1), 5000)
  )
  delete from public.encrypted_messages m using expired e where m.id = e.id;
  get diagnostics deleted_count = row_count;
  return deleted_count;
end;
$$;

create or replace function public.purge_old_audit_logs(retention_days integer default 90, batch_size integer default 5000)
returns integer
language plpgsql security definer set search_path = public
as $$
declare
  deleted_count integer;
begin
  with old_rows as (
    select id from public.audit_logs
    where created_at < now() - make_interval(days => least(greatest(coalesce(retention_days, 90), 30), 3650))
    order by created_at
    limit least(greatest(coalesce(batch_size, 5000), 1), 20000)
  )
  delete from public.audit_logs a using old_rows o where a.id = o.id;
  get diagnostics deleted_count = row_count;
  return deleted_count;
end;
$$;

revoke create on schema public from public, anon, authenticated;
grant usage on schema public to anon, authenticated;
revoke all on all tables in schema public from anon;
revoke all on all sequences in schema public from anon, authenticated;
revoke execute on all functions in schema public from public, anon;

grant execute on function public.is_conversation_member(uuid, uuid) to authenticated;
grant execute on function public.is_admin(uuid) to authenticated;
grant execute on function public.is_staff(uuid) to authenticated;
grant execute on function public.is_account_active(uuid) to authenticated;
grant execute on function public.create_direct_conversation(uuid) to authenticated;
grant execute on function public.send_encrypted_message(uuid, uuid, jsonb, uuid, integer, text) to authenticated;
grant execute on function public.toggle_block(uuid, boolean, text) to authenticated;
grant execute on function public.delete_message_for_everyone(uuid) to authenticated;
grant execute on function public.get_admin_metrics() to authenticated;
grant execute on function public.admin_set_suspension(uuid, boolean, integer) to authenticated;
grant execute on function public.admin_resolve_report(uuid, public.report_status, text) to authenticated;
grant execute on function public.revoke_device(uuid) to authenticated;
grant execute on function public.submit_report(uuid, uuid, text) to authenticated;
grant execute on function public.purge_expired_messages(integer) to service_role;
grant execute on function public.purge_old_audit_logs(integer, integer) to service_role;

alter default privileges in schema public revoke all on tables from anon;
alter default privileges in schema public revoke all on sequences from anon, authenticated;
alter default privileges in schema public revoke execute on functions from public, anon;
