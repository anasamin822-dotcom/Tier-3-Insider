-- Bound anonymous queue growth and serialize mutations of the shared document.
create table public.t3i_request_limits(window_start timestamptz not null, action text not null, calls int not null default 0, primary key(window_start,action));
alter table public.t3i_request_limits enable row level security;
revoke all on public.t3i_request_limits from anon,authenticated;
create function public.t3i_check_limit(action_name text,max_calls int) returns void language plpgsql security definer set search_path='' as $$
declare n int;
begin
insert into public.t3i_request_limits(window_start,action,calls) values(date_trunc('minute',now()),action_name,1) on conflict(window_start,action) do update set calls=public.t3i_request_limits.calls+1 returning calls into n;
if n>max_calls then raise exception 'Too many requests. Please try again in a minute.'; end if;
delete from public.t3i_request_limits where window_start<now()-interval '1 day';
end $$;
revoke all on function public.t3i_check_limit(text,int) from public,anon,authenticated;
