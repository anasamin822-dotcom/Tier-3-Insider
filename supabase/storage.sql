insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types) values ('tier3-verification','tier3-verification',false,5242880,array['image/jpeg','image/png','application/pdf']);
create policy t3i_private_upload on storage.objects for insert to anon,authenticated with check (bucket_id='tier3-verification' and name ~ '^[0-9a-f-]{36}\.(jpg|png|pdf)$');
create policy t3i_admin_read on storage.objects for select to authenticated using (bucket_id='tier3-verification' and public.t3i_is_admin());
create policy t3i_admin_delete on storage.objects for delete to authenticated using (bucket_id='tier3-verification' and public.t3i_is_admin());
