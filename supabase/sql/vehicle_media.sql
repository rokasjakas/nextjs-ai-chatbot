-- ============================================================
-- Automobilių problemos: nuotraukos IR video, problema – ir chate #automobiliai
--  * per QR kodą galima įkelti ir video (suspaudžiama telefone iki ~45 MB)
--  * programoje „Pranešti problemą“: nuotraukos / video įkeliami į #automobiliai kanalą,
--    o pati problema su jais įdedama į chatą (kaip ir per QR)
-- Reikia: vehicle_qr.sql (ir jo reikalavimų).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- the #automobiliai channel for a member who sees „Transportas“ (made / joined when missing)
create or replace function public.vehicles_channel_mine() returns uuid
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or not public.is_approved() or not public.fleet_viewer(auth.uid()) then
    raise exception 'Nėra teisės matyti „Transporto“.';
  end if;
  return public.vehicles_channel();
end $$;
revoke all on function public.vehicles_channel_mine() from public, anon;
grant execute on function public.vehicles_channel_mine() to authenticated;

-- one attachment of a chat message from a file path in #automobiliai
create or replace function public.vehicle_att(p_path text, p_name text default null, p_size bigint default null) returns jsonb
  language sql immutable set search_path = public as $$
  select case when p_path ~* '\.(mp4|m4v|mov|webm)$'
    then jsonb_build_object('type', 'file', 'path', p_path, 'name', coalesce(nullif(p_name, ''), 'video.' || lower(substring(p_path from '\.([a-zA-Z0-9]+)$'))),
                            'mime', case when p_path ~* '\.webm$' then 'video/webm' when p_path ~* '\.mov$' then 'video/quicktime' else 'video/mp4' end,
                            'size', p_size)
    else jsonb_build_object('type', 'image', 'path', p_path) end
$$;

-- a problem registered in the app → a message in #automobiliai with its photos / videos
create or replace function public.vehicle_problem_post(p_log uuid) returns uuid
  language plpgsql security definer set search_path = public as $$
declare l public.vehicle_logs; cid uuid; att jsonb := '[]'::jsonb; f jsonb; mid uuid; vname text;
begin
  select * into l from public.vehicle_logs where id = p_log;
  if l.id is null or l.kind <> 'problem' then raise exception 'Problema nerasta.'; end if;
  if not (l.created_by = auth.uid() or public.can_edit('fleet')) then raise exception 'Nėra teisės.'; end if;
  if (l.data ->> 'chat_msg') is not null then return (l.data ->> 'chat_msg')::uuid; end if;
  cid := public.vehicles_channel();
  for f in select * from jsonb_array_elements(coalesce(l.files, '[]'::jsonb)) loop
    if f ->> 'bucket' = 'chat-files' and (f ->> 'path') like cid::text || '/%' and jsonb_array_length(att) < 12 then
      att := att || public.vehicle_att(f ->> 'path', f ->> 'name', nullif(f ->> 'size', '')::bigint);
    end if;
  end loop;
  vname := coalesce(nullif(l.vehicle_name, ''), 'Automobilis');
  insert into public.messages (conversation_id, sender_id, body, attachments)
  values (cid, auth.uid(),
          '🚐 Problema: ' || vname || E'\n' || l.title
            || case when coalesce(trim(l.description), '') <> '' then E'\n' || left(trim(l.description), 3000) else '' end
            || E'\n' || case l.severity when 'stop' then '⛔ Negalima važiuoti' when 'low' then 'Galima važiuoti' else '⚠ Reikia greitai sutvarkyti' end,
          att)
  returning id into mid;
  update public.vehicle_logs set data = coalesce(data, '{}'::jsonb) || jsonb_build_object('chat_msg', mid) where id = l.id;
  return mid;
end $$;
revoke all on function public.vehicle_problem_post(uuid) from public, anon;
grant execute on function public.vehicle_problem_post(uuid) to authenticated;

-- QR page: photos (.jpg) and videos (.mp4 / .webm / .mov)
drop policy if exists "vehicle qr photos add" on storage.objects;
create policy "vehicle qr photos add" on storage.objects for insert to anon, authenticated
  with check (bucket_id = 'chat-files'
    and (storage.foldername(name))[1] = public.vehicles_channel_id()::text
    and storage.filename(name) ~ '^qr-[0-9a-f]{24,64}-[0-9a-z]{6,24}\.(jpg|mp4|webm|mov)$'
    and public.vehicle_token_ok(split_part(storage.filename(name), '-', 2)));

create or replace function public.vehicle_public_report(p_token text, p_name text, p_text text, p_severity text, p_files text[])
  returns uuid language plpgsql security definer set search_path = public as $$
declare v jsonb; vid text; cid uuid; who text; member boolean := false; sender uuid; rid uuid := gen_random_uuid();
        att jsonb := '[]'::jsonb; f text; vname text; sev text := coalesce(nullif(p_severity, ''), 'soon'); mid uuid; nv int := 0;
begin
  v := public.vehicle_by_token(p_token);
  if v is null then raise exception 'QR kodas nebegalioja.'; end if;
  vid := v ->> 'id';
  vname := coalesce(v ->> 'name', 'Automobilis') || coalesce(' (' || nullif(v ->> 'plate', '') || ')', '');
  if sev not in ('low','soon','stop') then sev := 'soon'; end if;
  if length(trim(coalesce(p_text, ''))) < 3 then raise exception 'Aprašyk problemą.'; end if;
  if auth.uid() is not null and public.is_approved() then
    member := true; sender := auth.uid(); who := public.my_name();
  else
    who := trim(coalesce(p_name, ''));
    if length(who) < 3 or position(' ' in who) = 0 then raise exception 'Įrašyk vardą ir pavardę.'; end if;
    select created_by into sender from public.vehicle_qr where token = p_token;
    if sender is null then select id into sender from public.profiles where role = 'admin' order by created_at limit 1; end if;
  end if;
  -- not too many at once from one code
  if (select count(*) from public.vehicle_reports where vehicle_id = vid and created_at > now() - interval '10 minutes') >= 5 then
    raise exception 'Per daug pranešimų – pabandyk po kelių minučių.';
  end if;
  cid := public.vehicles_channel();
  foreach f in array coalesce(p_files, '{}') loop
    if f like cid::text || '/qr-' || p_token || '-%' then
      if f ~* '\.(mp4|webm|mov)$' then
        if nv < 3 then att := att || public.vehicle_att(f); nv := nv + 1; end if;
      elsif jsonb_array_length(att) - nv < 6 then
        att := att || public.vehicle_att(f);
      end if;
    end if;
  end loop;
  insert into public.vehicle_reports (id, vehicle_id, vehicle_name, reporter_id, reporter_name, member, body, severity, files)
  values (rid, vid, vname, case when member then auth.uid() end, left(who, 120), member, left(trim(p_text), 4000), sev, att);
  insert into public.messages (conversation_id, sender_id, body, attachments, guest_name)
  values (cid, sender,
          '🚐 Problema: ' || vname || E'\n' || left(trim(p_text), 4000)
            || E'\n' || case sev when 'stop' then '⛔ Negalima važiuoti' when 'low' then 'Galima važiuoti' else '⚠ Reikia greitai sutvarkyti' end
            || case when member then '' else E'\nPranešė: ' || left(who, 120) || ' (ne narys, per QR)' end,
          att || jsonb_build_array(jsonb_build_object('type', 'vreport', 'id', rid)),
          case when member then null else left(who, 120) end)
  returning id into mid;
  update public.vehicle_reports set message_id = mid where id = rid;
  return rid;
end $$;

-- „Įtraukti į darbus“: videos stay videos
create or replace function public.vehicle_report_accept(p_id uuid) returns uuid
  language plpgsql security definer set search_path = public as $$
declare r public.vehicle_reports; lid uuid := gen_random_uuid(); fl jsonb;
begin
  if not public.can_edit('fleet') then raise exception 'Įtraukti į darbus gali tik tas, kas redaguoja „Transportą“.'; end if;
  select * into r from public.vehicle_reports where id = p_id for update;
  if r.id is null then raise exception 'Pranešimas nerastas.'; end if;
  if r.status = 'accepted' then return r.log_id; end if;
  select coalesce(jsonb_agg(case when e ->> 'type' = 'file'
           then jsonb_build_object('path', e ->> 'path', 'bucket', 'chat-files', 'type', coalesce(e ->> 'mime', 'video/mp4'), 'name', coalesce(e ->> 'name', 'video.mp4'))
           else jsonb_build_object('path', e ->> 'path', 'bucket', 'chat-files', 'type', 'image/jpeg', 'name', 'nuotrauka.jpg') end), '[]'::jsonb)
    into fl from jsonb_array_elements(r.files) e;
  insert into public.vehicle_logs (id, vehicle_id, vehicle_name, kind, log_date, title, description, severity, status, files, data, created_by, created_by_name)
  values (lid, r.vehicle_id, r.vehicle_name, 'problem', (r.created_at at time zone 'Europe/Vilnius')::date,
          left(split_part(r.body, E'\n', 1), 120), r.body, r.severity, 'open', fl,
          jsonb_build_object('via', 'qr', 'report_id', r.id, 'reporter', r.reporter_name, 'member', r.member, 'accepted_by', public.my_name(), 'chat_msg', r.message_id),
          auth.uid(), r.reporter_name);
  update public.vehicle_reports set status = 'accepted', accepted_by = auth.uid(), accepted_name = public.my_name(), accepted_at = now(), log_id = lid where id = p_id;
  return lid;
end $$;

revoke all on function public.vehicle_public_report(text, text, text, text, text[]) from public;
grant execute on function public.vehicle_public_report(text, text, text, text, text[]) to anon, authenticated;
revoke all on function public.vehicle_report_accept(uuid) from public, anon;
grant execute on function public.vehicle_report_accept(uuid) to authenticated;

notify pgrst, 'reload schema';
