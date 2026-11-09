create or replace function public.t3i_submit(queue text,payload jsonb) returns void language plpgsql security definer set search_path='' as $$
begin
perform public.t3i_check_limit('submissions',20);
perform 1 from public.t3i_store where id for update;
if queue not in ('pending_reviews','pending_seniors','pending_payments') or jsonb_typeof(payload)<>'object' or octet_length(payload::text)>100000 then raise exception 'Invalid submission'; end if;
if queue='pending_reviews' then
 if length(coalesce(payload->>'review_text','')) not between 150 and 6000 or length(coalesce(payload->>'college_name','')) not between 2 and 200 or jsonb_typeof(payload->'rating')<>'number' or (payload->>'rating')::numeric not between 1 and 5 then raise exception 'Invalid review'; end if;
 payload=payload||jsonb_build_object('upvotes',0,'verified',false,'created_at',now());
elsif queue='pending_seniors' then
 if length(coalesce(payload->>'alias','')) not between 2 and 80 or length(coalesce(payload->>'college','')) not between 2 and 200 then raise exception 'Alias and college required'; end if;
 payload=payload||jsonb_build_object('rating',4,'rating_count',0,'whatsapp',null);
else
 if length(coalesce(payload->>'email','')) not between 3 and 254 or length(coalesce(payload->>'txn_id','')) not between 3 and 100 then raise exception 'Invalid payment details'; end if;
 payload=payload||jsonb_build_object('amount',case when payload->>'type'='senior_chat' then 49 else 19 end);
end if;
if (select jsonb_array_length(data->queue) from public.t3i_store where id)>1000 then raise exception 'Queue full; please try later'; end if;
update public.t3i_store set data=jsonb_set(data,array[queue],coalesce(data->queue,'[]')||jsonb_build_array(payload||jsonb_build_object('id',gen_random_uuid()::text,'verified',false))) where id;
end $$;
