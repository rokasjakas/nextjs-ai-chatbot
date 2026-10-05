-- ============================================================
-- Transportas → automobilio QR kodas
--  * vehicle_qr      – kiekvieno automobilio unikalus (atsitiktinis, neatspėjamas) QR raktas
--  * vehicle_public(token)        – nuskenavus QR (be prisijungimo): svarbiausia automobilio info
--  * vehicle_public_report(...)   – „Registruoti problemą“: narys – su savo vardu, ne narys – įrašo vardą, pavardę;
--                                   problema su nuotraukomis įdedama į chato kanalą #automobiliai
--  * vehicle_reports              – užregistruotos (per QR) problemos
--  * vehicle_report_accept(id)    – chate atsakingas asmuo (kas redaguoja „Transportą“) spaudžia
--                                   „Įtraukti į darbus“ → problema įrašoma automobilio „Problemose“
--  * nuotraukos įkeliamos į chat-files/<#automobiliai kanalas>/qr-<raktas>-<…>.jpg
-- Reikia: vehicle_logs.sql, vehicle_logs2.sql, members_chat.sql, chat_slack.sql, guest_meetings.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.vehicle_qr (
  token       text primary key check (token ~ '^[0-9a-f]{24,64}$'),
  vehicle_id  text not null unique,
  created_by  uuid default auth.uid(),
  created_at  timestamptz not null default now()
);
alter table public.vehicle_qr enable row level security;
drop policy if exists "vehicle qr view" on public.vehicle_qr;
create policy "vehicle qr view" on public.vehicle_qr for select to authenticated using (public.can_view('fleet'));
drop policy if exists "vehicle qr add" on public.vehicle_qr;
create policy "vehicle qr add" on public.vehicle_qr for insert to authenticated with check (public.can_edit('fleet'));
drop policy if exists "vehicle qr remove" on public.vehicle_qr;
create policy "vehicle qr remove" on public.vehicle_qr for delete to authenticated using (public.can_edit('fleet'));
revoke all on public.vehicle_qr from anon;
grant select, insert, delete on public.vehicle_qr to authenticated;

create table if not exists public.vehicle_reports (
  id             uuid primary key default gen_random_uuid(),
  vehicle_id     text not null,
  vehicle_name   text,
  reporter_id    uuid,
  reporter_name  text not null,
  member         boolean not null default false,
  body           text not null,
  severity       text not null default 'soon' check (severity in ('low','soon','stop')),
  files          jsonb not null default '[]'::jsonb,
  message_id     uuid,
  status         text not null default 'new' check (status in ('new','accepted')),
  accepted_by    uuid,
  accepted_name  text,
  accepted_at    timestamptz,
  log_id         uuid,
  created_at     timestamptz not null default now()
);
create index if not exists vehicle_reports_vehicle on public.vehicle_reports (vehicle_id, created_at desc);
alter table public.vehicle_reports enable row level security;
drop policy if exists "vehicle reports view" on public.vehicle_reports;
create policy "vehicle reports view" on public.vehicle_reports for select to authenticated using (public.can_view('fleet'));
revoke all on public.vehicle_reports from anon;
grant select on public.vehicle_reports to authenticated;

-- a problem reported by someone who is not a member has no member as its author
alter table public.vehicle_logs alter column created_by drop not null;

create or replace function public.fleet_viewer(uid uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles p where p.id = uid and (
    p.role = 'admin' or exists (select 1 from public.role_permissions rp
                                where rp.role = p.role and rp.section = 'fleet' and (rp.can_view or rp.can_edit))))
$$;

-- the #automobiliai channel (made when missing); its members: who sees „Transportas“
create or replace function public.vehicles_channel_id() returns uuid
  language sql stable security definer set search_path = public as $$
  select id from public.conversations
   where kind = 'channel' and archived_at is null and lower(replace(title, '#', '')) = 'automobiliai'
   order by created_at limit 1
$$;
create or replace function public.vehicles_channel() returns uuid
  language plpgsql security definer set search_path = public as $$
declare cid uuid := public.vehicles_channel_id();
begin
  if cid is null then
    insert into public.conversations (kind, title, topic, is_private)
    values ('channel', 'automobiliai', 'Automobilių problemos (per QR kodą)', true) returning id into cid;
  end if;
  insert into public.conversation_members (conversation_id, user_id)
  select cid, p.id from public.profiles p where public.fleet_viewer(p.id) and public.user_can_chat(p.id)
  on conflict do nothing;
  return cid;
end $$;

create or replace function public.vehicle_by_token(p_token text) returns jsonb
  language sql stable security definer set search_path = public as $$
  select x from public.vehicle_qr q
    join public.app_state s on s.key = 'vehicles'
    cross join lateral jsonb_array_elements(case when jsonb_typeof(s.data) = 'array' then s.data else '[]'::jsonb end) x
   where q.token = p_token and x ->> 'id' = q.vehicle_id
   limit 1
$$;

create or replace function public.my_name() returns text
  language sql stable security definer set search_path = public as $$
  select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), nullif(trim(p.full_name), ''), p.email)
    from public.profiles p where p.id = auth.uid()
$$;

-- what anyone who scans the code sees
create or replace function public.vehicle_public(p_token text) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare v jsonb; vid text; oil record; chk record; res jsonb; me text;
begin
  v := public.vehicle_by_token(p_token);
  if v is null then return null; end if;
  vid := v ->> 'id';
  select l.log_date, l.mileage, l.engine_hours, l.data -> 'oil' as oil into oil from public.vehicle_logs l
   where l.vehicle_id = vid and l.kind = 'service' and l.category = 'Tepalo keitimas' order by l.log_date desc, l.created_at desc limit 1;
  select l.log_date, l.data ->> 'condition' as cond into chk from public.vehicle_logs l
   where l.vehicle_id = vid and l.kind = 'check' order by l.log_date desc, l.created_at desc limit 1;
  if auth.uid() is not null and public.is_approved() then me := public.my_name(); end if;
  res := jsonb_build_object(
    'id', vid, 'name', v ->> 'name', 'plate', v ->> 'plate', 'docs', coalesce(v -> 'docs', '{}'::jsonb), 'repair', v -> 'repair',
    'km', (select max(mileage) from public.vehicle_logs where vehicle_id = vid),
    'hours', (select max(engine_hours) from public.vehicle_logs where vehicle_id = vid),
    'oil', case when oil.log_date is null then null else jsonb_build_object('date', oil.log_date, 'km', oil.mileage, 'next', oil.oil) end,
    'check', case when chk.log_date is null then null else jsonb_build_object('date', chk.log_date, 'condition', chk.cond) end,
    'problems', coalesce((select jsonb_agg(jsonb_build_object('title', title, 'severity', severity, 'date', log_date) order by log_date desc)
                            from (select title, severity, log_date from public.vehicle_logs
                                   where vehicle_id = vid and kind = 'problem' and status = 'open' order by log_date desc limit 10) p), '[]'::jsonb),
    'channel', public.vehicles_channel(),
    'me', me);
  return res;
end $$;

-- „Registruoti problemą“ from the QR page
create or replace function public.vehicle_public_report(p_token text, p_name text, p_text text, p_severity text, p_files text[])
  returns uuid language plpgsql security definer set search_path = public as $$
declare v jsonb; vid text; cid uuid; who text; member boolean := false; sender uuid; rid uuid := gen_random_uuid();
        att jsonb := '[]'::jsonb; f text; vname text; sev text := coalesce(nullif(p_severity, ''), 'soon'); mid uuid;
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
    if f like cid::text || '/qr-' || p_token || '-%' and jsonb_array_length(att) < 6 then
      att := att || jsonb_build_object('type', 'image', 'path', f);
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

-- the person in charge: „Įtraukti į darbus“ → the vehicle's problems
create or replace function public.vehicle_report_accept(p_id uuid) returns uuid
  language plpgsql security definer set search_path = public as $$
declare r public.vehicle_reports; lid uuid := gen_random_uuid(); fl jsonb;
begin
  if not public.can_edit('fleet') then raise exception 'Įtraukti į darbus gali tik tas, kas redaguoja „Transportą“.'; end if;
  select * into r from public.vehicle_reports where id = p_id for update;
  if r.id is null then raise exception 'Pranešimas nerastas.'; end if;
  if r.status = 'accepted' then return r.log_id; end if;
  select coalesce(jsonb_agg(jsonb_build_object('path', e ->> 'path', 'bucket', 'chat-files', 'type', 'image/jpeg', 'name', 'nuotrauka.jpg')), '[]'::jsonb)
    into fl from jsonb_array_elements(r.files) e;
  insert into public.vehicle_logs (id, vehicle_id, vehicle_name, kind, log_date, title, description, severity, status, files, data, created_by, created_by_name)
  values (lid, r.vehicle_id, r.vehicle_name, 'problem', (r.created_at at time zone 'Europe/Vilnius')::date,
          left(split_part(r.body, E'\n', 1), 120), r.body, r.severity, 'open', fl,
          jsonb_build_object('via', 'qr', 'report_id', r.id, 'reporter', r.reporter_name, 'member', r.member, 'accepted_by', public.my_name()),
          auth.uid(), r.reporter_name);
  -- (the stamp trigger writes the accepting member as the author; the reporter stays in data.reporter)
  update public.vehicle_reports set status = 'accepted', accepted_by = auth.uid(), accepted_name = public.my_name(), accepted_at = now(), log_id = lid where id = p_id;
  return lid;
end $$;

revoke all on function public.vehicle_public(text), public.vehicle_public_report(text, text, text, text, text[]) from public;
grant execute on function public.vehicle_public(text), public.vehicle_public_report(text, text, text, text, text[]) to anon, authenticated;
revoke all on function public.vehicle_report_accept(uuid) from public, anon;
grant execute on function public.vehicle_report_accept(uuid) to authenticated;
revoke all on function public.vehicles_channel(), public.vehicle_by_token(text), public.fleet_viewer(uuid), public.my_name() from public, anon;

create or replace function public.vehicle_token_ok(p_token text) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.vehicle_qr where token = p_token)
$$;

-- the photos from the QR page (also without signing in): only into #automobiliai, only with a valid code in the name
drop policy if exists "vehicle qr photos add" on storage.objects;
create policy "vehicle qr photos add" on storage.objects for insert to anon, authenticated
  with check (bucket_id = 'chat-files'
    and (storage.foldername(name))[1] = public.vehicles_channel_id()::text
    and storage.filename(name) ~ '^qr-[0-9a-f]{24,64}-[0-9a-z]{6,24}\.jpg$'
    and public.vehicle_token_ok(split_part(storage.filename(name), '-', 2)));
grant execute on function public.vehicles_channel_id(), public.vehicle_token_ok(text) to anon, authenticated;

notify pgrst, 'reload schema';
