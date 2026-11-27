-- ============================================================
-- Transportas: „Kuro pylimas“ ir tie patys pasirinkimai per QR kodą
--  * vehicle_logs.kind 'fuel' – kuro pylimas: data, rida, litrai (data.liters), suma (cost),
--    komentaras (description), kvito nuotrauka (files)
--  * įregistruoti gali kiekvienas, kas mato „Transportą“ (kaip problemą ar įvykį)
--  * QR puslapis: „Pranešti apie problemą“, „Registruoti įvykį“, „Kuro pylimas“, „Apie automobilį“;
--    ne narys (neprisijungęs) privalo įrašyti vardą, pavardę ir el. paštą
--  * vehicle_public_log(...) – įvykis arba kuro pylimas per QR (įrašoma į automobilio istoriją,
--    įvykis dar įdedamas į chatą #automobiliai)
-- Reikia: vehicle_qr.sql, vehicle_media.sql, vehicle_loc.sql, vehicle_incident.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.vehicle_logs drop constraint if exists vehicle_logs_kind_check;
alter table public.vehicle_logs add constraint vehicle_logs_kind_check check (kind in ('service','problem','check','incident','fuel'));

drop policy if exists "fleet logs add" on public.vehicle_logs;
create policy "fleet logs add" on public.vehicle_logs for insert to authenticated
  with check (public.can_view('fleet') and created_by = auth.uid() and (kind in ('problem','check','incident','fuel') or public.can_edit('fleet')));
drop policy if exists "fleet logs change" on public.vehicle_logs;
create policy "fleet logs change" on public.vehicle_logs for update to authenticated
  using (public.can_edit('fleet') or created_by = auth.uid())
  with check (public.can_edit('fleet') or (created_by = auth.uid() and kind in ('problem','check','incident','fuel')));

-- who reported through the QR code: the e-mail of someone who is not a member
alter table public.vehicle_reports add column if not exists reporter_email text;

-- a visitor who is not a member: first and last name and an e-mail
create or replace function public.vehicle_qr_guest(p_name text, p_email text) returns text
  language plpgsql immutable set search_path = public as $$
declare who text := trim(coalesce(p_name, '')); em text := lower(trim(coalesce(p_email, '')));
begin
  if length(who) < 3 or position(' ' in who) = 0 then raise exception 'Įrašyk vardą ir pavardę.'; end if;
  if em !~ '^[^@\s]+@[^@\s]+\.[^@\s]{2,}$' or length(em) > 200 then raise exception 'Įrašyk el. paštą.'; end if;
  return em;
end $$;

-- „Pranešti apie problemą“ from the QR page: now with the e-mail (the old form without it is replaced)
drop function if exists public.vehicle_public_report(text, text, text, text, text[], jsonb);
create or replace function public.vehicle_public_report(p_token text, p_name text, p_text text, p_severity text, p_files text[], p_loc jsonb default null, p_email text default null)
  returns uuid language plpgsql security definer set search_path = public as $$
declare loc jsonb := public.vehicle_loc_clean(p_loc); v jsonb; vid text; cid uuid; who text; em text; member boolean := false; sender uuid; rid uuid := gen_random_uuid();
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
    em := public.vehicle_qr_guest(p_name, p_email); who := trim(p_name);
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
  insert into public.vehicle_reports (id, vehicle_id, vehicle_name, reporter_id, reporter_name, reporter_email, member, body, severity, files, loc)
  values (rid, vid, vname, case when member then auth.uid() end, left(who, 120), em, member, left(trim(p_text), 4000), sev, att, loc);
  insert into public.messages (conversation_id, sender_id, body, attachments, guest_name)
  values (cid, sender,
          '🚐 Problema: ' || vname || E'\n' || left(trim(p_text), 4000)
            || E'\n' || case sev when 'stop' then '⛔ Negalima važiuoti' when 'low' then 'Galima važiuoti' else '⚠ Reikia greitai sutvarkyti' end
            || E'\n🕒 ' || to_char(now() at time zone 'Europe/Vilnius', 'YYYY-MM-DD HH24:MI')
            || public.vehicle_loc_txt(loc)
            || case when member then '' else E'\nPranešė: ' || left(who, 120) || ', ' || em || ' (ne narys, per QR)' end,
          att || jsonb_build_array(jsonb_build_object('type', 'vreport', 'id', rid)),
          case when member then null else left(who, 120) end)
  returning id into mid;
  update public.vehicle_reports set message_id = mid where id = rid;
  return rid;
end $$;
revoke all on function public.vehicle_public_report(text, text, text, text, text[], jsonb, text) from public;
grant execute on function public.vehicle_public_report(text, text, text, text, text[], jsonb, text) to anon, authenticated;

-- „Registruoti įvykį“ and „Kuro pylimas“ from the QR page: straight into the vehicle's history
--  p_kind 'incident': p_title – kas nutiko, p_text – aprašymas, p_data {time, comment}
--  p_kind 'fuel':     p_text – komentaras, p_data {liters, eur, km}
create or replace function public.vehicle_public_log(p_token text, p_kind text, p_name text, p_email text, p_title text, p_text text,
                                                    p_files text[], p_loc jsonb default null, p_data jsonb default '{}'::jsonb)
  returns uuid language plpgsql security definer set search_path = public as $$
declare loc jsonb := public.vehicle_loc_clean(p_loc); v jsonb; vid text; cid uuid; who text; em text; member boolean := false; sender uuid;
        lid uuid := gen_random_uuid(); fl jsonb := '[]'::jsonb; att jsonb := '[]'::jsonb; f text; vname text; vtitle text;
        d jsonb := coalesce(p_data, '{}'::jsonb); dat jsonb; liters numeric; eur numeric; km int; tm text; cm text; nv int := 0;
begin
  v := public.vehicle_by_token(p_token);
  if v is null then raise exception 'QR kodas nebegalioja.'; end if;
  if p_kind not in ('incident','fuel') then raise exception 'Netinkamas įrašas.'; end if;
  vid := v ->> 'id';
  vname := coalesce(v ->> 'name', 'Automobilis') || coalesce(' (' || nullif(v ->> 'plate', '') || ')', '');
  if auth.uid() is not null and public.is_approved() then
    member := true; sender := auth.uid(); who := public.my_name();
  else
    em := public.vehicle_qr_guest(p_name, p_email); who := trim(p_name);
    select created_by into sender from public.vehicle_qr where token = p_token;
    if sender is null then select id into sender from public.profiles where role = 'admin' order by created_at limit 1; end if;
  end if;
  if (select count(*) from public.vehicle_logs where vehicle_id = vid and data ->> 'via' = 'qr' and created_at > now() - interval '10 minutes') >= 5 then
    raise exception 'Per daug įrašų – pabandyk po kelių minučių.';
  end if;
  if jsonb_typeof(d -> 'km') = 'number' and (d ->> 'km')::numeric >= 0 and (d ->> 'km')::numeric < 10000000 then km := round((d ->> 'km')::numeric); end if;
  if p_kind = 'fuel' then
    if length(trim(coalesce(p_text, ''))) < 3 then raise exception 'Parašyk komentarą dėl pylimo.'; end if;
    if jsonb_typeof(d -> 'liters') = 'number' and (d ->> 'liters')::numeric > 0 and (d ->> 'liters')::numeric < 10000 then liters := round((d ->> 'liters')::numeric, 2); end if;
    if jsonb_typeof(d -> 'eur') = 'number' and (d ->> 'eur')::numeric >= 0 and (d ->> 'eur')::numeric < 100000 then eur := round((d ->> 'eur')::numeric, 2); end if;
    vtitle := 'Kuro pylimas';
  else
    if length(trim(coalesce(p_title, ''))) < 3 then raise exception 'Parašyk, kas nutiko.'; end if;
    if length(trim(coalesce(p_text, ''))) < 3 then raise exception 'Aprašyk įvykį.'; end if;
    vtitle := left(trim(p_title), 120);
    tm := case when coalesce(d ->> 'time', '') ~ '^\d{2}:\d{2}$' then d ->> 'time' end;
    cm := nullif(left(trim(coalesce(d ->> 'comment', '')), 2000), '');
  end if;
  cid := public.vehicles_channel();
  foreach f in array coalesce(p_files, '{}') loop
    if f like cid::text || '/qr-' || p_token || '-%' then
      if f ~* '\.(mp4|webm|mov)$' then
        if p_kind = 'incident' and nv < 3 then
          fl := fl || jsonb_build_object('path', f, 'bucket', 'chat-files', 'type', 'video/' || case when f ~* '\.webm$' then 'webm' when f ~* '\.mov$' then 'quicktime' else 'mp4' end, 'name', 'video' || substring(f from '\.[a-zA-Z0-9]+$'));
          att := att || public.vehicle_att(f); nv := nv + 1;
        end if;
      elsif jsonb_array_length(fl) - nv < 6 then
        fl := fl || jsonb_build_object('path', f, 'bucket', 'chat-files', 'type', 'image/jpeg', 'name', case when p_kind = 'fuel' then 'kvitas.jpg' else 'nuotrauka.jpg' end);
        att := att || public.vehicle_att(f);
      end if;
    end if;
  end loop;
  dat := jsonb_build_object('via', 'qr', 'reporter', left(who, 120), 'member', member, 'reported_at', now())
         || case when em is not null then jsonb_build_object('email', em) else '{}'::jsonb end
         || case when loc is not null then jsonb_build_object('loc', loc) else '{}'::jsonb end
         || case when p_kind = 'fuel' then jsonb_build_object('liters', liters)
                 else jsonb_build_object('time', tm, 'comment', cm) end;
  insert into public.vehicle_logs (id, vehicle_id, vehicle_name, kind, log_date, mileage, title, description, cost, status, files, data, created_by, created_by_name)
  values (lid, vid, vname, p_kind, (now() at time zone 'Europe/Vilnius')::date, km, vtitle, left(trim(p_text), 4000), eur, 'done', fl, dat,
          case when member then auth.uid() end, left(who, 120));
  -- an incident goes to the #automobiliai chat too
  if p_kind = 'incident' then
    insert into public.messages (conversation_id, sender_id, body, attachments, guest_name)
    values (cid, sender,
            '💥 Įvykis: ' || vname || E'\n' || vtitle || E'\n' || left(trim(p_text), 3000)
              || case when cm is not null then E'\nKomentaras: ' || cm else '' end
              || E'\n🕒 ' || to_char(now() at time zone 'Europe/Vilnius', 'YYYY-MM-DD') || coalesce(' ' || tm, to_char(now() at time zone 'Europe/Vilnius', ' HH24:MI'))
              || public.vehicle_loc_txt(loc)
              || case when member then '' else E'\nPranešė: ' || left(who, 120) || ', ' || em || ' (ne narys, per QR)' end,
            att, case when member then null else left(who, 120) end);
  end if;
  return lid;
end $$;
revoke all on function public.vehicle_public_log(text, text, text, text, text, text, text[], jsonb, jsonb) from public;
grant execute on function public.vehicle_public_log(text, text, text, text, text, text, text[], jsonb, jsonb) to anon, authenticated;

notify pgrst, 'reload schema';
