begin;
create or replace function public.t3i_auth_email() returns text language sql stable security definer set search_path='' as $$
select lower(email) from auth.users where id=auth.uid() and email_confirmed_at is not null and not coalesce(is_anonymous,false)
$$;
create or replace function public.t3i_submit_payment(p_txn_id text,p_type text) returns void language plpgsql security definer set search_path='' as $$
begin raise exception 'Payments are paused. Do not send money.' using errcode='42501'; end $$;
create or replace function public.t3i_approve_senior(p_pending_id text) returns text language plpgsql security definer set search_path='' as $$
declare d jsonb; p jsonb; sid text; u uuid;
begin
if not coalesce(public.t3i_is_admin(),false) then raise exception 'Admin access required' using errcode='42501'; end if;
select data into d from public.t3i_store where id for update;
select x into p from jsonb_array_elements(d->'pending_seniors') x where x->>'id'=p_pending_id;
if p is null then raise exception 'Pending registration not found'; end if;
select id into u from auth.users where id::text=p->>'user_id' and lower(email)=lower(p->>'email') and email_confirmed_at is not null;
if u is null then raise exception 'A verified member account is required for this registration'; end if;
sid := gen_random_uuid()::text;
insert into public.t3i_senior_accounts(senior_id,email) values(sid,lower(p->>'email'));
d := jsonb_set(d,'{pending_seniors}',coalesce((select jsonb_agg(x) from jsonb_array_elements(d->'pending_seniors') x where x->>'id'<>p_pending_id),'[]'::jsonb));
d := jsonb_set(d,'{seniors}',coalesce(d->'seniors','[]')||jsonb_build_array(p||jsonb_build_object('id',sid,'verified',true,'rating',0,'rating_count',0)));
update public.t3i_store set data=d where id;
return sid;
end $$;
revoke all on function public.t3i_approve_senior(text) from public,anon;
grant execute on function public.t3i_approve_senior(text) to authenticated;
CREATE OR REPLACE FUNCTION public.t3i_read()
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare d jsonb; r jsonb; s jsonb;
begin
select data into d from public.t3i_store where id;
if public.t3i_is_admin() then return d; end if;
select coalesce(jsonb_agg(jsonb_build_object('id',x->'id','college_name',x->'college_name','state',x->'state','department',x->'department','review_text',x->'review_text','rating',x->'rating','upvotes',x->'upvotes','verified',x->'verified','created_at',x->'created_at','year_of_study',x->'year_of_study')),'[]') into r from jsonb_array_elements(d->'reviews') x;
select coalesce(jsonb_agg(jsonb_build_object('id',x->'id','alias',x->'alias','college',x->'college','branch',x->'branch','year_of_study',x->'year_of_study','bio',x->'bio','rating',x->'rating','rating_count',x->'rating_count','chat_available',exists(select 1 from public.t3i_senior_accounts sa where sa.senior_id=x->>'id'))),'[]') into s from jsonb_array_elements(d->'seniors') x;
return jsonb_build_object('reviews',r,'seniors',s,'pending_reviews','[]'::jsonb,'pending_seniors','[]'::jsonb,'pending_payments','[]'::jsonb,'paid_emails','[]'::jsonb,'messages','[]'::jsonb);
end $function$
;
CREATE OR REPLACE FUNCTION public.t3i_chat_send(p_senior_id text, p_fresher_id uuid, p_body text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_role text; v_id uuid; v_ts timestamptz;
begin
  if auth.uid() is null then raise exception 'Login required' using errcode = '42501'; end if;
  perform public.t3i_check_limit('chat_send', 30);
  if public.t3i_auth_email() is null then raise exception 'Verified email required' using errcode='42501'; end if;
  if not exists(select 1 from public.t3i_senior_accounts sa where sa.senior_id=p_senior_id) then raise exception 'This senior is not available for chat yet'; end if;
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
end $function$
;
commit;
CREATE OR REPLACE FUNCTION public.t3i_submit(queue text, payload jsonb)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
  perform public.t3i_check_limit('submissions', 20);
  perform 1 from public.t3i_store where id for update;
  if queue not in ('pending_reviews', 'pending_seniors') or jsonb_typeof(payload) <> 'object' or octet_length(payload::text) > 100000 then raise exception 'Invalid submission'; end if;
  if queue = 'pending_reviews' then
    if length(coalesce(payload->>'review_text','')) not between 150 and 6000 or length(coalesce(payload->>'college_name','')) not between 2 and 200 or jsonb_typeof(payload->'rating') <> 'number' or (payload->>'rating')::numeric not between 1 and 5 then raise exception 'Invalid review'; end if;
    payload = payload || jsonb_build_object('upvotes', 0, 'verified', false, 'created_at', now());
  else
    if auth.uid() is null or public.t3i_auth_email() is null then raise exception 'Login required to register as a senior' using errcode = '42501'; end if;
    if length(coalesce(payload->>'alias','')) not between 2 and 80 or length(coalesce(payload->>'college','')) not between 2 and 200 then raise exception 'Alias and college required'; end if;
    payload = payload || jsonb_build_object('rating', 4, 'rating_count', 0, 'whatsapp', null, 'email', public.t3i_auth_email(), 'user_id', auth.uid()::text);
  end if;
  if (select coalesce(jsonb_array_length(data->queue), 0) from public.t3i_store where id) > 1000 then raise exception 'Queue full; please try later'; end if;
  update public.t3i_store set data = jsonb_set(data, array[queue], coalesce(data->queue, '[]'::jsonb) || jsonb_build_array(payload || jsonb_build_object('id', gen_random_uuid()::text, 'verified', false))) where id;
end $function$
;
