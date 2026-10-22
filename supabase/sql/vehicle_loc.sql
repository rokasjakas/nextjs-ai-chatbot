-- ============================================================
-- Automobilio problema: vieta (GPS), data ir laikas
--  * pranešant (programoje ir per QR) telefonas nustato vietą – ji ir laikas
--    įrašomi prie problemos ir rodomi chato #automobiliai žinutėje (nuoroda į žemėlapį)
-- Reikia: vehicle_media.sql, vehicle_media2.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.vehicle_reports add column if not exists loc jsonb;

-- a place from the phone: only numbers kept
create or replace function public.vehicle_loc_clean(p jsonb) returns jsonb
  language sql immutable set search_path = public as $$
  select case when jsonb_typeof(p -> 'lat') = 'number' and jsonb_typeof(p -> 'lng') = 'number'
               and abs((p ->> 'lat')::numeric) <= 90 and abs((p ->> 'lng')::numeric) <= 180
    then jsonb_build_object('lat', round((p ->> 'lat')::numeric, 6), 'lng', round((p ->> 'lng')::numeric, 6),
                            'acc', case when jsonb_typeof(p -> 'acc') = 'number' then round((p ->> 'acc')::numeric) end)
    else null end
$$;
-- the line in the chat message
create or replace function public.vehicle_loc_txt(p jsonb) returns text
  language sql immutable set search_path = public as $$
  select case when public.vehicle_loc_clean(p) is null then ''
    else E'\n📍 [Vieta žemėlapyje](https://www.google.com/maps?q=' || (p ->> 'lat') || ',' || (p ->> 'lng') || ')'
         || case when jsonb_typeof(p -> 'acc') = 'number' then ' (±' || round((p ->> 'acc')::numeric) || ' m)' else '' end end
$$;

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
            || E'\n' || case l.severity when 'stop' then '⛔ Negalima važiuoti' when 'low' then 'Galima važiuoti' else '⚠ Reikia greitai sutvarkyti' end
            || E'\n🕒 ' || to_char(coalesce(l.created_at, now()) at time zone 'Europe/Vilnius', 'YYYY-MM-DD HH24:MI')
            || public.vehicle_loc_txt(l.data -> 'loc'),
          att)
  returning id into mid;
  update public.vehicle_logs set data = coalesce(data, '{}'::jsonb) || jsonb_build_object('chat_msg', mid) where id = l.id;
  return mid;
end $$;
revoke all on function public.vehicle_problem_post(uuid) from public, anon;
grant execute on function public.vehicle_problem_post(uuid) to authenticated;

-- the QR page sends the place too (the old form without it is replaced)
drop function if exists public.vehicle_public_report(text, text, text, text, text[]);
create or replace function public.vehicle_public_report(p_token text, p_name text, p_text text, p_severity text, p_files text[], p_loc jsonb default null)
  returns uuid language plpgsql security definer set search_path = public as $$
declare loc jsonb := public.vehicle_loc_clean(p_loc); v jsonb; vid text; cid uuid; who text; member boolean := false; sender uuid; rid uuid := gen_random_uuid();
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
  insert into public.vehicle_reports (id, vehicle_id, vehicle_name, reporter_id, reporter_name, member, body, severity, files, loc)
  values (rid, vid, vname, case when member then auth.uid() end, left(who, 120), member, left(trim(p_text), 4000), sev, att, loc);
  insert into public.messages (conversation_id, sender_id, body, attachments, guest_name)
  values (cid, sender,
          '🚐 Problema: ' || vname || E'\n' || left(trim(p_text), 4000)
            || E'\n' || case sev when 'stop' then '⛔ Negalima važiuoti' when 'low' then 'Galima važiuoti' else '⚠ Reikia greitai sutvarkyti' end
            || E'\n🕒 ' || to_char(now() at time zone 'Europe/Vilnius', 'YYYY-MM-DD HH24:MI')
            || public.vehicle_loc_txt(loc)
            || case when member then '' else E'\nPranešė: ' || left(who, 120) || ' (ne narys, per QR)' end,
          att || jsonb_build_array(jsonb_build_object('type', 'vreport', 'id', rid)),
          case when member then null else left(who, 120) end)
  returning id into mid;
  update public.vehicle_reports set message_id = mid where id = rid;
  return rid;
end $$;
revoke all on function public.vehicle_public_report(text, text, text, text, text[], jsonb) from public;
grant execute on function public.vehicle_public_report(text, text, text, text, text[], jsonb) to anon, authenticated;

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
          jsonb_build_object('via', 'qr', 'report_id', r.id, 'reporter', r.reporter_name, 'member', r.member, 'accepted_by', public.my_name(), 'chat_msg', r.message_id) || case when r.loc is not null then jsonb_build_object('loc', r.loc, 'reported_at', r.created_at) else jsonb_build_object('reported_at', r.created_at) end,
          auth.uid(), r.reporter_name);
  update public.vehicle_reports set status = 'accepted', accepted_by = auth.uid(), accepted_name = public.my_name(), accepted_at = now(), log_id = lid where id = p_id;
  return lid;
end $$;
revoke all on function public.vehicle_report_accept(uuid) from public, anon;
grant execute on function public.vehicle_report_accept(uuid) to authenticated;

notify pgrst, 'reload schema';
