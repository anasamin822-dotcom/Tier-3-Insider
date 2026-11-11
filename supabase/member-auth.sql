-- Real member authentication: verified-email chat, server-side entitlements.
-- All member data lives behind security-definer RPCs; tables are unreachable directly.
begin;

create table public.t3i_senior_accounts(
  senior_id text primary key,
  email text not null,
  created_at timestamptz not null default now()
);
alter table public.t3i_senior_accounts enable row level security;
revoke all on public.t3i_senior_accounts from anon, authenticated;

create table public.t3i_entitlements(
  email text not null,
  kind text not null check (kind in ('senior_chat','review_access')),
  granted_by uuid,
  created_at timestamptz not null default now(),
  primary key(email, kind)
);
alter table public.t3i_entitlements enable row level security;
revoke all on public.t3i_entitlements from anon, authenticated;

create table public.t3i_messages(
  id uuid primary key default gen_random_uuid(),
  senior_id text not null,
  fresher_id uuid not null references auth.users(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  sender_role text not null check (sender_role in ('fresher','senior')),
  body text not null check (char_length(body) between 1 and 2000),
  created_at timestamptz not null default now()
);
create index t3i_messages_thread_idx on public.t3i_messages(senior_id, fresher_id, created_at);
alter table public.t3i_messages enable row level security;
revoke all on public.t3i_messages from anon, authenticated;

-- Verified email of the caller, straight from auth.users (never from client input).
create function public.t3i_auth_email() returns text language sql stable security definer set search_path='' as $$
  select lower(email) from auth.users where id = auth.uid()
$$;
revoke all on function public.t3i_auth_email() from public, anon, authenticated;

create function public.t3i_is_senior(p_senior_id text) returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.t3i_senior_accounts sa where sa.senior_id = p_senior_id and lower(sa.email) = public.t3i_auth_email())
$$;
revoke all on function public.t3i_is_senior(text) from public, anon, authenticated;

create function public.t3i_has_access(p_kind text) returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(public.t3i_is_admin(), false) or exists(select 1 from public.t3i_entitlements e where lower(e.email) = public.t3i_auth_email() and e.kind = p_kind)
$$;
revoke all on function public.t3i_has_access(text) from public, anon, authenticated;

-- What the logged-in member is allowed to see/do. No emails of other users are ever returned.
create function public.t3i_my_profile() returns jsonb language plpgsql stable security definer set search_path='' as $$
declare e text;
begin
  e := public.t3i_auth_email();
  if e is null then return null; end if;
  return jsonb_build_object(
    'email', e,
    'user_id', auth.uid(),
    'is_admin', coalesce(public.t3i_is_admin(), false),
    'senior_chat', public.t3i_has_access('senior_chat'),
    'senior_ids', coalesce((select jsonb_agg(sa.senior_id) from public.t3i_senior_accounts sa where lower(sa.email) = e), '[]'::jsonb)
  );
end $$;
revoke all on function public.t3i_my_profile() from public, anon;
grant execute on function public.t3i_my_profile() to authenticated;

create function public.t3i_chat_send(p_senior_id text, p_fresher_id uuid, p_body text) returns jsonb language plpgsql security definer set search_path='' as $$
declare v_role text; v_id uuid; v_ts timestamptz;
begin
  if auth.uid() is null then raise exception 'Login required' using errcode = '42501'; end if;
  perform public.t3i_check_limit('chat_send', 30);
  if not exists(select 1 from public.t3i_store s, jsonb_array_elements(s.data->'seniors') x where s.id and x->>'id' = p_senior_id)
    then raise exception 'Unknown senior'; end if;
  if public.t3i_is_senior(p_senior_id) then
    v_role := 'senior';
    if not exists(select 1 from public.t3i_messages m where m.senior_id = p_senior_id and m.fresher_id = p_fresher_id)
      then raise exception 'No such conversation'; end if;
  else
    v_role := 'fresher';
    if p_fresher_id is distinct from auth.uid() then raise exception 'Cannot message as another user' using errcode = '42501'; end if;
    if not public.t3i_has_access('senior_chat') then raise exception 'Chat access is locked for this account' using errcode = '42501'; end if;
  end if;
  if p_body is null or char_length(btrim(p_body)) < 1 then raise exception 'Message cannot be empty'; end if;
  if char_length(p_body) > 2000 then raise exception 'Message too long (max 2000 characters)'; end if;
  insert into public.t3i_messages(senior_id, fresher_id, sender_id, sender_role, body)
    values (p_senior_id, p_fresher_id, auth.uid(), v_role, btrim(p_body)) returning id, created_at into v_id, v_ts;
  return jsonb_build_object('id', v_id, 'ts', v_ts, 'role', v_role);
end $$;
revoke all on function public.t3i_chat_send(text, uuid, text) from public, anon;
grant execute on function public.t3i_chat_send(text, uuid, text) to authenticated;

-- Participants and admin only. Fresher identity is returned only as a role flag, never an email.
create function public.t3i_chat_read(p_senior_id text, p_fresher_id uuid) returns jsonb language plpgsql stable security definer set search_path='' as $$
begin
  if auth.uid() is null then return null; end if;
  if not (coalesce(public.t3i_is_admin(), false) or auth.uid() = p_fresher_id or public.t3i_is_senior(p_senior_id)) then return null; end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object('id', m.id, 'role', m.sender_role, 'body', m.body, 'ts', m.created_at, 'mine', m.sender_id = auth.uid()) order by m.created_at)
    from public.t3i_messages m where m.senior_id = p_senior_id and m.fresher_id = p_fresher_id
  ), '[]'::jsonb);
end $$;
revoke all on function public.t3i_chat_read(text, uuid) from public, anon;
grant execute on function public.t3i_chat_read(text, uuid) to authenticated;

-- Senior inbox: thread list for a senior linked to the caller (or admin). Masked fresher label.
create function public.t3i_chat_threads(p_senior_id text) returns jsonb language plpgsql stable security definer set search_path='' as $$
begin
  if auth.uid() is null then return null; end if;
  if not (coalesce(public.t3i_is_admin(), false) or public.t3i_is_senior(p_senior_id)) then return null; end if;
  return coalesce((
    select jsonb_agg(t.t order by t.t->>'last_ts' desc) from (
      select jsonb_build_object(
        'fresher_id', m.fresher_id,
        'label', 'Fresher ' || upper(left(m.fresher_id::text, 4)),
        'last_body', (array_agg(m.body order by m.created_at desc))[1],
        'last_ts', max(m.created_at),
        'count', count(*)
      ) as t
      from public.t3i_messages m where m.senior_id = p_senior_id group by m.fresher_id
    ) t
  ), '[]'::jsonb);
end $$;
revoke all on function public.t3i_chat_threads(text) from public, anon;
grant execute on function public.t3i_chat_threads(text) to authenticated;

-- Payment submission: email and user are stamped from the verified session; amount is fixed server-side.
-- Submitting never grants access. Only the admin can grant, after checking the UPI credit manually.
create function public.t3i_submit_payment(p_txn_id text, p_type text) returns void language plpgsql security definer set search_path='' as $$
declare e text;
begin
  if auth.uid() is null then raise exception 'Login required' using errcode = '42501'; end if;
  perform public.t3i_check_limit('payment_submit', 10);
  e := public.t3i_auth_email();
  if p_type not in ('senior_chat', 'review_access') then raise exception 'Invalid payment type'; end if;
  if p_txn_id is null or char_length(btrim(p_txn_id)) not between 6 and 60 then raise exception 'Enter a valid UPI transaction ID'; end if;
  perform 1 from public.t3i_store where id for update;
  if (select coalesce(jsonb_array_length(data->'pending_payments'), 0) from public.t3i_store where id) > 200 then raise exception 'Queue full; please try later'; end if;
  update public.t3i_store set data = jsonb_set(data, '{pending_payments}',
    coalesce(data->'pending_payments', '[]'::jsonb) || jsonb_build_array(jsonb_build_object(
      'id', gen_random_uuid()::text, 'email', e, 'user_id', auth.uid()::text, 'txn_id', btrim(p_txn_id),
      'amount', case when p_type = 'senior_chat' then 49 else 19 end,
      'type', p_type, 'date', now(), 'verified', false)))
  where id;
end $$;
revoke all on function public.t3i_submit_payment(text, text) from public, anon;
grant execute on function public.t3i_submit_payment(text, text) to authenticated;

create function public.t3i_grant_access(p_email text, p_kind text) returns void language plpgsql security definer set search_path='' as $$
begin
  if not coalesce(public.t3i_is_admin(), false) then raise exception 'Admin access required' using errcode = '42501'; end if;
  if p_kind not in ('senior_chat', 'review_access') or p_email is null or p_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then raise exception 'Invalid grant'; end if;
  insert into public.t3i_entitlements(email, kind, granted_by) values (lower(btrim(p_email)), p_kind, auth.uid()) on conflict do nothing;
end $$;
revoke all on function public.t3i_grant_access(text, text) from public, anon;
grant execute on function public.t3i_grant_access(text, text) to authenticated;

create function public.t3i_revoke_access(p_email text, p_kind text) returns void language plpgsql security definer set search_path='' as $$
begin
  if not coalesce(public.t3i_is_admin(), false) then raise exception 'Admin access required' using errcode = '42501'; end if;
  delete from public.t3i_entitlements where email = lower(btrim(p_email)) and kind = p_kind;
end $$;
revoke all on function public.t3i_revoke_access(text, text) from public, anon;
grant execute on function public.t3i_revoke_access(text, text) to authenticated;

create function public.t3i_link_senior(p_senior_id text, p_email text) returns void language plpgsql security definer set search_path='' as $$
begin
  if not coalesce(public.t3i_is_admin(), false) then raise exception 'Admin access required' using errcode = '42501'; end if;
  if p_email is null or p_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then raise exception 'Invalid email'; end if;
  insert into public.t3i_senior_accounts(senior_id, email) values (p_senior_id, lower(btrim(p_email)))
    on conflict(senior_id) do update set email = excluded.email;
end $$;
revoke all on function public.t3i_link_senior(text, text) from public, anon;
grant execute on function public.t3i_link_senior(text, text) to authenticated;

-- Senior registration and payment submissions now require a verified session;
-- the server stamps the caller's verified email onto the record. Reviews stay open to everyone.
create or replace function public.t3i_submit(queue text, payload jsonb) returns void language plpgsql security definer set search_path='' as $$
begin
  perform public.t3i_check_limit('submissions', 20);
  perform 1 from public.t3i_store where id for update;
  if queue not in ('pending_reviews', 'pending_seniors') or jsonb_typeof(payload) <> 'object' or octet_length(payload::text) > 100000 then raise exception 'Invalid submission'; end if;
  if queue = 'pending_reviews' then
    if length(coalesce(payload->>'review_text','')) not between 150 and 6000 or length(coalesce(payload->>'college_name','')) not between 2 and 200 or jsonb_typeof(payload->'rating') <> 'number' or (payload->>'rating')::numeric not between 1 and 5 then raise exception 'Invalid review'; end if;
    payload = payload || jsonb_build_object('upvotes', 0, 'verified', false, 'created_at', now());
  else
    if auth.uid() is null then raise exception 'Login required to register as a senior' using errcode = '42501'; end if;
    if length(coalesce(payload->>'alias','')) not between 2 and 80 or length(coalesce(payload->>'college','')) not between 2 and 200 then raise exception 'Alias and college required'; end if;
    payload = payload || jsonb_build_object('rating', 4, 'rating_count', 0, 'whatsapp', null, 'email', public.t3i_auth_email(), 'user_id', auth.uid()::text);
  end if;
  if (select coalesce(jsonb_array_length(data->queue), 0) from public.t3i_store where id) > 1000 then raise exception 'Queue full; please try later'; end if;
  update public.t3i_store set data = jsonb_set(data, array[queue], coalesce(data->queue, '[]'::jsonb) || jsonb_build_array(payload || jsonb_build_object('id', gen_random_uuid()::text, 'verified', false))) where id;
end $$;
revoke all on function public.t3i_submit(text, jsonb) from public;
grant execute on function public.t3i_submit(text, jsonb) to anon, authenticated;

commit;