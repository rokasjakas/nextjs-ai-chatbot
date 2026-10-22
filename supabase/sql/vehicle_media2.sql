-- ============================================================
-- Automobilio problema: video įkeliamas fone, jau pateikus problemą
--  * problema išsaugoma ir įdedama į #automobiliai iškart (be video)
--  * video suspaudžiamas ir įkeliamas fone, o baigus – pridedamas prie problemos
--    ir įdedamas į chatą kaip atsakymas į problemos žinutę (matosi ir kanale)
-- Reikia: vehicle_media.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- in the app: videos of a problem that was already saved
create or replace function public.vehicle_problem_add_media(p_log uuid, p_files jsonb) returns uuid
  language plpgsql security definer set search_path = public as $$
declare l public.vehicle_logs; cid uuid; f jsonb; fl jsonb := '[]'::jsonb; att jsonb := '[]'::jsonb; mid uuid; par uuid;
begin
  select * into l from public.vehicle_logs where id = p_log;
  if l.id is null then raise exception 'Problema nerasta.'; end if;
  if not (l.created_by = auth.uid() or public.can_edit('fleet')) then raise exception 'Nėra teisės.'; end if;
  cid := public.vehicles_channel();
  for f in select * from jsonb_array_elements(coalesce(p_files, '[]'::jsonb)) loop
    if (f ->> 'path') like cid::text || '/vl-' || p_log::text || '-%' and jsonb_array_length(fl) < 6 then
      fl := fl || jsonb_build_object('path', f ->> 'path', 'bucket', 'chat-files', 'type', coalesce(f ->> 'type', 'video/mp4'),
                                     'name', coalesce(f ->> 'name', 'video.mp4'), 'size', f -> 'size', 'at', now());
      att := att || public.vehicle_att(f ->> 'path', f ->> 'name', nullif(f ->> 'size', '')::bigint);
    end if;
  end loop;
  if jsonb_array_length(fl) = 0 then return null; end if;
  update public.vehicle_logs set files = coalesce(files, '[]'::jsonb) || fl where id = l.id;
  if l.kind <> 'problem' then return null; end if;
  par := nullif(l.data ->> 'chat_msg', '')::uuid;
  if par is not null and not exists (select 1 from public.messages where id = par) then par := null; end if;
  insert into public.messages (conversation_id, sender_id, body, attachments, parent_id, also_channel)
  values (cid, auth.uid(), '🎬 Video prie problemos: ' || coalesce(nullif(l.vehicle_name, ''), 'Automobilis') || ' – ' || l.title,
          att, par, par is not null)
  returning id into mid;
  return mid;
end $$;
revoke all on function public.vehicle_problem_add_media(uuid, jsonb) from public, anon;
grant execute on function public.vehicle_problem_add_media(uuid, jsonb) to authenticated;

-- QR page: videos of a report that was already sent (for 3 hours after it)
create or replace function public.vehicle_public_report_media(p_token text, p_report uuid, p_files text[]) returns uuid
  language plpgsql security definer set search_path = public as $$
declare v jsonb; r public.vehicle_reports; cid uuid; f text; att jsonb := '[]'::jsonb; nv int; m record; mid uuid;
begin
  v := public.vehicle_by_token(p_token);
  if v is null then raise exception 'QR kodas nebegalioja.'; end if;
  select * into r from public.vehicle_reports where id = p_report and vehicle_id = v ->> 'id' and created_at > now() - interval '3 hours' for update;
  if r.id is null then raise exception 'Pranešimas nerastas.'; end if;
  cid := public.vehicles_channel();
  select count(*) into nv from jsonb_array_elements(r.files) e where e ->> 'type' = 'file';
  foreach f in array coalesce(p_files, '{}') loop
    if f like cid::text || '/qr-' || p_token || '-%' and f ~* '\.(mp4|webm|mov)$' and nv < 3
       and not exists (select 1 from jsonb_array_elements(r.files) e where e ->> 'path' = f) then
      att := att || public.vehicle_att(f); nv := nv + 1;
    end if;
  end loop;
  if jsonb_array_length(att) = 0 then return null; end if;
  update public.vehicle_reports set files = files || att where id = r.id;
  -- already taken into the work list: the videos go to the problem too
  if r.log_id is not null then
    update public.vehicle_logs set files = coalesce(files, '[]'::jsonb) || (
      select coalesce(jsonb_agg(jsonb_build_object('path', e ->> 'path', 'bucket', 'chat-files', 'type', coalesce(e ->> 'mime', 'video/mp4'), 'name', coalesce(e ->> 'name', 'video.mp4'))), '[]'::jsonb)
        from jsonb_array_elements(att) e)
     where id = r.log_id;
  end if;
  select id, sender_id, guest_name into m from public.messages where id = r.message_id;
  insert into public.messages (conversation_id, sender_id, body, attachments, guest_name, parent_id, also_channel)
  values (cid, coalesce(m.sender_id, (select created_by from public.vehicle_qr where token = p_token)),
          '🎬 Video prie problemos: ' || coalesce(r.vehicle_name, 'Automobilis'),
          att, m.guest_name, m.id, m.id is not null)
  returning id into mid;
  return mid;
end $$;
revoke all on function public.vehicle_public_report_media(text, uuid, text[]) from public;
grant execute on function public.vehicle_public_report_media(text, uuid, text[]) to anon, authenticated;

notify pgrst, 'reload schema';
