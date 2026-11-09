begin;
create table public.t3i_admins(user_id uuid primary key references auth.users(id));
create table public.t3i_store(id boolean primary key default true check(id), data jsonb not null);
alter table public.t3i_admins enable row level security;
alter table public.t3i_store enable row level security;
revoke all on public.t3i_admins, public.t3i_store from anon, authenticated;
create function public.t3i_is_admin() returns boolean language sql stable security definer set search_path='' as $$ select exists(select 1 from public.t3i_admins where user_id=auth.uid()) $$;
revoke all on function public.t3i_is_admin() from public;
grant execute on function public.t3i_is_admin() to authenticated;
create policy admin_only on public.t3i_store for all to authenticated using (public.t3i_is_admin()) with check (public.t3i_is_admin());
create function public.t3i_read() returns jsonb language plpgsql stable security definer set search_path='' as $$
declare d jsonb; r jsonb; s jsonb;
begin
select data into d from public.t3i_store where id;
if public.t3i_is_admin() then return d; end if;
select coalesce(jsonb_agg(jsonb_build_object('id',x->'id','college_name',x->'college_name','state',x->'state','department',x->'department','review_text',x->'review_text','rating',x->'rating','upvotes',x->'upvotes','verified',x->'verified','created_at',x->'created_at','year_of_study',x->'year_of_study')),'[]') into r from jsonb_array_elements(d->'reviews') x;
select coalesce(jsonb_agg(jsonb_build_object('id',x->'id','alias',x->'alias','college',x->'college','branch',x->'branch','year_of_study',x->'year_of_study','bio',x->'bio','rating',x->'rating','rating_count',x->'rating_count')),'[]') into s from jsonb_array_elements(d->'seniors') x;
return jsonb_build_object('reviews',r,'seniors',s,'pending_reviews','[]'::jsonb,'pending_seniors','[]'::jsonb,'pending_payments','[]'::jsonb,'paid_emails','[]'::jsonb,'messages','[]'::jsonb);
end $$;
create function public.t3i_admin_write(payload jsonb) returns void language plpgsql security definer set search_path='' as $$
begin
if not public.t3i_is_admin() then raise exception 'Admin access required' using errcode='42501'; end if;
if jsonb_typeof(payload)<>'object' or octet_length(payload::text)>5000000 then raise exception 'Invalid payload'; end if;
update public.t3i_store set data=payload where id;
end $$;
create function public.t3i_submit(queue text,payload jsonb) returns void language plpgsql security definer set search_path='' as $$
begin
if queue not in ('pending_reviews','pending_seniors','pending_payments') or jsonb_typeof(payload)<>'object' or octet_length(payload::text)>100000 then raise exception 'Invalid submission'; end if;
if queue='pending_reviews' and (length(coalesce(payload->>'review_text',''))<20 or length(coalesce(payload->>'college_name',''))<2) then raise exception 'Review and college required'; end if;
if queue='pending_seniors' and (length(coalesce(payload->>'alias',''))<2 or length(coalesce(payload->>'college',''))<2) then raise exception 'Alias and college required'; end if;
if queue='pending_payments' and (length(coalesce(payload->>'email',''))<3 or length(coalesce(payload->>'txn_id',''))<3) then raise exception 'Payment details required'; end if;
if (select jsonb_array_length(data->queue) from public.t3i_store where id)>1000 then raise exception 'Queue full; please try later'; end if;
update public.t3i_store set data=jsonb_set(data,array[queue],coalesce(data->queue,'[]')||jsonb_build_array(payload||jsonb_build_object('id',gen_random_uuid()::text,'verified',false))) where id;
end $$;
create function public.t3i_vote(review_id text) returns void language plpgsql security definer set search_path='' as $$
begin
-- Public counters are not authentication or a trust score. Atomic update prevents overwriting other data.
update public.t3i_store set data=jsonb_set(data,'{reviews}',(select jsonb_agg(case when x->>'id'=review_id then jsonb_set(x,'{upvotes}',to_jsonb(coalesce((x->>'upvotes')::int,0)+1)) else x end) from jsonb_array_elements(data->'reviews') x)) where id;
end $$;
revoke all on function public.t3i_read(),public.t3i_admin_write(jsonb),public.t3i_submit(text,jsonb),public.t3i_vote(text) from public;
grant execute on function public.t3i_read(),public.t3i_submit(text,jsonb),public.t3i_vote(text) to anon,authenticated;
grant execute on function public.t3i_admin_write(jsonb) to authenticated;
commit;
