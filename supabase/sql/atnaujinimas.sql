-- ============================================================
-- EventSolutions App — VISI naujausi duomenų bazės pakeitimai viename faile
-- (chato teisės, pranešimai, el. paštas, failai chate, kalendorius,
-- narių trynimas, pasiūlymai, projektai, chatas kaip Slack, vaizdo skambučiai, įrangos nuotraukos ir išdavimai, žmonių archyvas ir bookingas).
-- Supabase → SQL Editor → įklijuok VISĄ → Run. Saugu paleisti kelis kartus.
-- ============================================================


-- >>>>>>>>>> chat_access.sql
-- ============================================================
-- Kas gali naudotis chatu: nauja skiltis „chat“ teisių lentelėje
-- (Admin → „Ką gali kiekvienas lygis“). Lygis be chato nemato jokių
-- pokalbių, žinučių ar jų nuotraukų, ir jam negalima parašyti.
-- Paleisti PO members_chat.sql ir chat_reactions.sql.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people'));

-- pradžioje chatu naudojasi visi lygiai (Admin skiltyje galima išjungti)
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('office','chat',true,true), ('tech','chat',true,true),
  ('freelance','chat',true,true), ('runner','chat',true,true)
on conflict (role, section) do nothing;

-- ar konkretus narys gali naudotis chatu
create or replace function public.user_can_chat(uid uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((
    select case when p.role = 'admin' then true
                when p.role in ('pm','office','tech','freelance','runner') then
                  coalesce((select rp.can_view or rp.can_edit from public.role_permissions rp
                            where rp.role = p.role and rp.section = 'chat'), false)
                else false end
    from public.profiles p where p.id = uid), false)
$$;
grant execute on function public.user_can_chat(uuid) to authenticated;

-- pokalbius mato tik tie, kam leista naudotis chatu
create or replace function public.is_conv_member(cid uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select public.is_approved() and public.user_can_chat(auth.uid()) and (
    exists (select 1 from public.conversations c where c.id = cid and c.kind = 'general')
    or exists (select 1 from public.conversation_members m where m.conversation_id = cid and m.user_id = auth.uid())
  )
$$;

create or replace function public.chat_direct(other uuid) returns uuid
  language plpgsql security definer set search_path = public as $$
declare cid uuid;
begin
  if not public.is_approved() or not public.user_can_chat(auth.uid()) then raise exception 'Nėra prieigos prie chato.'; end if;
  if other = auth.uid() then raise exception 'Negalima rašyti sau.'; end if;
  if not public.user_can_chat(other) then raise exception 'Šis narys chatu nesinaudoja.'; end if;
  select c.id into cid from public.conversations c
   where c.kind = 'direct'
     and exists (select 1 from public.conversation_members m where m.conversation_id = c.id and m.user_id = auth.uid())
     and exists (select 1 from public.conversation_members m where m.conversation_id = c.id and m.user_id = other)
   limit 1;
  if cid is null then
    insert into public.conversations (kind, created_by) values ('direct', auth.uid()) returning id into cid;
    insert into public.conversation_members (conversation_id, user_id) values (cid, auth.uid()), (cid, other);
  end if;
  return cid;
end $$;

create or replace function public.chat_group(title text, member_ids uuid[]) returns uuid
  language plpgsql security definer set search_path = public as $$
declare cid uuid;
begin
  if not public.is_approved() or not public.user_can_chat(auth.uid()) then raise exception 'Nėra prieigos prie chato.'; end if;
  insert into public.conversations (kind, title, created_by) values ('group', nullif(trim(title), ''), auth.uid()) returning id into cid;
  insert into public.conversation_members (conversation_id, user_id)
  select cid, p.id from public.profiles p
   where (p.id = auth.uid() or p.id = any(member_ids)) and public.user_can_chat(p.id)
  on conflict do nothing;
  return cid;
end $$;

create or replace function public.chat_group_add(cid uuid, member_ids uuid[]) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.conversations where id = cid and kind = 'group') or not public.is_conv_member(cid) then
    raise exception 'Nėra prieigos.';
  end if;
  insert into public.conversation_members (conversation_id, user_id)
  select cid, p.id from public.profiles p
   where p.id = any(member_ids) and public.user_can_chat(p.id)
  on conflict do nothing;
end $$;


-- >>>>>>>>>> notifications.sql
-- ============================================================
-- Pranešimai (telefone ir kompiuteryje) ir grupių trynimas.
--  * profiles.notify_prefs — ką pranešti, nutildyti pokalbiai, tylos valandos
--  * push_subscriptions    — įrenginiai, kuriuose įjungti pranešimai
--  * chat_group_delete     — grupę ištrina jos kūrėjas arba Admin
-- Paleisti PO chat_access.sql. Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

alter table public.profiles add column if not exists notify_prefs jsonb not null default '{}'::jsonb;

create table if not exists public.push_subscriptions (
  endpoint   text primary key,
  user_id    uuid not null references auth.users(id) on delete cascade,
  p256dh     text not null,
  auth       text not null,
  user_agent text,
  created_at timestamptz not null default now()
);
create index if not exists push_subscriptions_user_idx on public.push_subscriptions (user_id);

alter table public.push_subscriptions enable row level security;
drop policy if exists "own devices" on public.push_subscriptions;
create policy "own devices" on public.push_subscriptions
  for select to authenticated using (user_id = auth.uid());
drop policy if exists "remove own device" on public.push_subscriptions;
create policy "remove own device" on public.push_subscriptions
  for delete to authenticated using (user_id = auth.uid());

-- įrenginio registracija (tas pats įrenginys galėjo būti kito nario — perrašoma)
create or replace function public.push_register(p_endpoint text, p_p256dh text, p_auth text, p_ua text) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not public.is_approved() then raise exception 'Nėra prieigos.'; end if;
  if p_endpoint !~ '^https://' then raise exception 'Netinkamas adresas.'; end if;
  insert into public.push_subscriptions (endpoint, user_id, p256dh, auth, user_agent)
  values (p_endpoint, auth.uid(), p_p256dh, p_auth, left(p_ua, 300))
  on conflict (endpoint) do update set user_id = auth.uid(), p256dh = excluded.p256dh, auth = excluded.auth,
                                       user_agent = excluded.user_agent, created_at = now();
end $$;
grant execute on function public.push_register(text, text, text, text) to authenticated;

-- grupės kūrėjas ir pokalbių sąraše
drop function if exists public.chat_overview();
create function public.chat_overview() returns table (
  id uuid, kind text, title text, last_message_at timestamptz, members uuid[],
  last_body text, last_sender uuid, last_attachments int, unread int, created_by uuid)
  language sql stable security definer set search_path = public as $$
  select c.id, c.kind, c.title, c.last_message_at,
         coalesce((select array_agg(m.user_id) from public.conversation_members m where m.conversation_id = c.id), '{}'),
         lm.body, lm.sender_id, coalesce(jsonb_array_length(lm.attachments), 0),
         (select count(*)::int from public.messages x
           where x.conversation_id = c.id and x.deleted_at is null and x.sender_id <> auth.uid()
             and x.created_at > coalesce((select m.last_read_at from public.conversation_members m
                                          where m.conversation_id = c.id and m.user_id = auth.uid()), now() - interval '7 days')),
         c.created_by
  from public.conversations c
  left join lateral (select body, sender_id, attachments from public.messages x
                      where x.conversation_id = c.id and x.deleted_at is null
                      order by x.created_at desc limit 1) lm on true
  where public.is_conv_member(c.id)
  order by (c.kind = 'general') desc, c.last_message_at desc
$$;
grant execute on function public.chat_overview() to authenticated;

-- ištrinti grupę (su visomis žinutėmis) gali jos kūrėjas arba Admin
create or replace function public.chat_group_delete(cid uuid) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.conversations c where c.id = cid and c.kind = 'group'
                 and (c.created_by = auth.uid() or public.is_admin())) then
    raise exception 'Ištrinti gali tik grupės kūrėjas arba administratorius.';
  end if;
  delete from public.conversations where id = cid;
end $$;
grant execute on function public.chat_group_delete(uuid) to authenticated;

-- ištrintos grupės nuotraukas gali pašalinti jos kūrėjas arba Admin
drop policy if exists "chat files delete by owner" on storage.objects;
create policy "chat files delete by owner" on storage.objects
  for delete to authenticated using (
    bucket_id = 'chat-files' and exists (
      select 1 from public.conversations c
      where c.id::text = (storage.foldername(name))[1] and (c.created_by = auth.uid() or public.is_admin())));


-- >>>>>>>>>> mail.sql
-- ============================================================
-- El. paštas (atskiras puslapis): kiekvieno nario @eventsolutions.lt pašto
-- dėžutės prisijungimas. Slaptažodis saugomas užšifruotas, jį skaito
-- tik „mail“ funkcija — per programėlę jo niekas (net Admin) nemato.
-- Kas gali naudotis paštu — Admin → „Ką gali kiekvienas lygis“ →
-- „El. paštas“ (pradžioje: Admin ir Office).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people'));

insert into public.role_permissions (role, section, can_view, can_edit) values
  ('office','mail',true,true), ('tech','mail',false,false),
  ('freelance','mail',false,false), ('runner','mail',false,false)
on conflict (role, section) do nothing;
create table if not exists public.mail_accounts (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  email      text not null,
  secret     text not null,
  updated_at timestamptz not null default now()
);
alter table public.mail_accounts add column if not exists settings jsonb not null default '{}'::jsonb;
alter table public.mail_accounts add column if not exists state    jsonb not null default '{}'::jsonb;

-- pareigos profilyje (rodomos ir el. laiško paraše)
alter table public.profiles add column if not exists job_title text;

-- RLS be taisyklių: prie lentelės prieina tik serverio funkcija
alter table public.mail_accounts enable row level security;
revoke all on public.mail_accounts from anon, authenticated;

-- ------------------------------------------------------------
-- Automatinis atsakymas („out of office“): kas 10 min. „mail“ funkcija
-- patikrina naujus laiškus tų, kurie jį įsijungė. Naudojamas tas pats
-- CRON_SECRET kaip automobilių priminimams (paimamas iš to darbo).
-- ------------------------------------------------------------
create extension if not exists pg_cron;
create extension if not exists pg_net;
do $$
declare secret text;
begin
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
    from cron.job where jobname = 'vehicle-reminders-daily';
  if secret is null or secret = 'PAKEISK_SLAPTAZODI' then
    raise notice 'Nerastas CRON_SECRET (vehicle-reminders-daily). Automatiniai atsakymai neveiks, kol nepaleisi mail_cron dalies su slaptažodžiu.';
    return;
  end if;
  perform cron.unschedule(jobid) from cron.job where jobname = 'mail-auto-reply';
  perform cron.schedule('mail-auto-reply', '*/10 * * * *', format($job$
    select net.http_post(
      url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/mail',
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', %L),
      body    := '{"action":"cron"}'::jsonb,
      timeout_milliseconds := 120000
    );
  $job$, secret));
end $$;


-- >>>>>>>>>> chat_files.sql
-- ============================================================
-- Chate — bet kokie failai iki 200 MB (PDF, Excel, video, ZIP…).
-- Paleisti PO notifications.sql. Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
--
-- SVARBU: Supabase turi ir bendrą viso projekto failo dydžio ribą:
-- Storage → Settings → „Upload file size limit“. Nemokamame plane ji
-- ne didesnė nei 50 MB; 200 MB leidžia tik Pro planas.
-- ============================================================
update storage.buckets
   set file_size_limit = 209715200,          -- 200 MB
       allowed_mime_types = null             -- bet koks failo tipas
 where id = 'chat-files';

-- pokalbių sąraše: ar paskutinė žinutė buvo failas, ar nuotrauka
drop function if exists public.chat_overview();
create function public.chat_overview() returns table (
  id uuid, kind text, title text, last_message_at timestamptz, members uuid[],
  last_body text, last_sender uuid, last_attachments int, unread int, created_by uuid, last_att_kind text)
  language sql stable security definer set search_path = public as $$
  select c.id, c.kind, c.title, c.last_message_at,
         coalesce((select array_agg(m.user_id) from public.conversation_members m where m.conversation_id = c.id), '{}'),
         lm.body, lm.sender_id, coalesce(jsonb_array_length(lm.attachments), 0),
         (select count(*)::int from public.messages x
           where x.conversation_id = c.id and x.deleted_at is null and x.sender_id <> auth.uid()
             and x.created_at > coalesce((select m.last_read_at from public.conversation_members m
                                          where m.conversation_id = c.id and m.user_id = auth.uid()), now() - interval '7 days')),
         c.created_by,
         lm.attachments -> 0 ->> 'type'
  from public.conversations c
  left join lateral (select body, sender_id, attachments from public.messages x
                      where x.conversation_id = c.id and x.deleted_at is null
                      order by x.created_at desc limit 1) lm on true
  where public.is_conv_member(c.id)
  order by (c.kind = 'general') desc, c.last_message_at desc
$$;
grant execute on function public.chat_overview() to authenticated;


-- >>>>>>>>>> calendar.sql
-- ============================================================
-- Pagrindinio puslapio kalendorius (susitikimai, įvykiai) ir
-- asmeninis užduočių (to do) sąrašas.
--  * meetings — įvykį mato jo kūrėjas ir pakviesti nariai
--  * todos    — kiekvieno nario asmeninės užduotys
-- Paleisti PO notifications.sql. Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.meetings (
  id          uuid primary key default gen_random_uuid(),
  title       text not null check (char_length(title) between 1 and 200),
  meet_date   date not null,
  start_time  time,
  end_time    time,
  location    text not null default '',
  description text not null default '',
  attendees   uuid[] not null default '{}',   -- pakviesti nariai
  emails      text[] not null default '{}',   -- pakviesti ne nariai (el. paštu)
  notified    jsonb not null default '{}'::jsonb, -- kam jau išsiųsta (tvarko funkcija)
  created_by  uuid not null default auth.uid() references auth.users(id) on delete cascade,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists meetings_date_idx on public.meetings (meet_date);
create index if not exists meetings_attendees_idx on public.meetings using gin (attendees);

alter table public.meetings enable row level security;
drop policy if exists "see own meetings" on public.meetings;
create policy "see own meetings" on public.meetings
  for select to authenticated using (public.is_approved() and (created_by = auth.uid() or auth.uid() = any(attendees)));
drop policy if exists "add meetings" on public.meetings;
create policy "add meetings" on public.meetings
  for insert to authenticated with check (public.is_approved() and created_by = auth.uid());
drop policy if exists "change own meetings" on public.meetings;
create policy "change own meetings" on public.meetings
  for update to authenticated using (created_by = auth.uid()) with check (created_by = auth.uid());
drop policy if exists "delete own meetings" on public.meetings;
create policy "delete own meetings" on public.meetings
  for delete to authenticated using (created_by = auth.uid());

create table if not exists public.todos (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null default auth.uid() references auth.users(id) on delete cascade,
  title       text not null check (char_length(title) between 1 and 200),
  due_date    date,
  due_time    time,
  description text not null default '',
  created_at  timestamptz not null default now()
);
create index if not exists todos_user_idx on public.todos (user_id);

alter table public.todos enable row level security;
drop policy if exists "own todos" on public.todos;
create policy "own todos" on public.todos
  for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid() and public.is_approved());

-- kalendorius atsinaujina realiu laiku (ištrynimo įvykiui reikia visų stulpelių)
alter table public.meetings replica identity full;
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'meetings') then
    execute 'alter publication supabase_realtime add table public.meetings';
  end if;
end $$;


-- >>>>>>>>>> admin_delete.sql
-- ============================================================
-- Admin gali visam laikui ištrinti narį (Admin → vartotojų sąrašas → 🗑).
-- Kartu ištrinamas profilis, jo žinutės, reakcijos, užduotys, jo sukurti
-- susitikimai, pašto prisijungimas ir pranešimų įrenginiai.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================
create or replace function public.admin_delete_user(uid uuid) returns void
  language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_admin() then raise exception 'Tik administratorius gali trinti narius.'; end if;
  if uid = auth.uid() then raise exception 'Savęs ištrinti negalima.'; end if;
  if (select role from public.profiles where id = uid) = 'admin'
     and (select count(*) from public.profiles where role = 'admin') <= 1 then
    raise exception 'Negalima ištrinti paskutinio administratoriaus.';
  end if;
  -- iš susitikimų, į kuriuos jis buvo pakviestas
  update public.meetings set attendees = array_remove(attendees, uid) where uid = any(attendees);
  delete from auth.users where id = uid;
end $$;
revoke all on function public.admin_delete_user(uuid) from public, anon;
grant execute on function public.admin_delete_user(uuid) to authenticated;


-- >>>>>>>>>> offers.sql
-- ============================================================
-- Pasiūlymai ir Projektai (Ofisas) + naujas lygis „Projektų vadovas“.
--  * role 'pm' — Projektų vadovas
--  * skiltys: 'offers' (Pasiūlymai), 'jobs' (Projektai)
--  * offers  — komerciniai pasiūlymai (juodraštis / galutinis)
--  * jobs    — projektai, sukurti iš galutinio pasiūlymo (PDF be kainų)
--  * saugykla 'job-files' — projektų PDF
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- naujas lygis ----------
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check
  check (role in ('pending','admin','pm','office','tech','freelance','runner','blocked'));

alter table public.role_permissions drop constraint if exists role_permissions_role_check;
alter table public.role_permissions add constraint role_permissions_role_check
  check (role in ('pm','office','tech','freelance','runner'));
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people'));

-- numatytosios teisės (Admin skiltyje galima pakeisti)
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','offers',true,true), ('pm','jobs',true,true), ('pm','events',true,true), ('pm','rentals',true,true),
  ('pm','projects',true,true), ('pm','venues',true,true), ('pm','fleet',true,false), ('pm','inventory',true,false),
  ('pm','load',true,false), ('pm','rules',true,false), ('pm','stats',true,false), ('pm','chat',true,true), ('pm','mail',true,true),
  ('office','offers',false,false), ('office','jobs',true,false),
  ('tech','offers',false,false), ('tech','jobs',true,false),
  ('freelance','offers',false,false), ('freelance','jobs',false,false),
  ('runner','offers',false,false), ('runner','jobs',false,false)
on conflict (role, section) do nothing;

create or replace function public.is_approved() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','pm','office','tech','freelance','runner'), false)
$$;

create or replace function public.user_can_chat(uid uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((
    select case when p.role = 'admin' then true
                when p.role in ('pm','office','tech','freelance','runner') then
                  coalesce((select rp.can_view or rp.can_edit from public.role_permissions rp
                            where rp.role = p.role and rp.section = 'chat'), false)
                else false end
    from public.profiles p where p.id = uid), false)
$$;

drop policy if exists "team sees members" on public.profiles;
create policy "team sees members" on public.profiles
  for select to authenticated using (
    id = auth.uid() or public.is_admin()
    or (public.is_approved() and role in ('admin','pm','office','tech','freelance','runner'))
  );

-- pasiūlymų nustatymai (rekvizitai, PVM) ir kainų atmintis — redaguoja „Pasiūlymai“
create or replace function public.app_state_can_edit(k text) returns boolean
  language sql stable security definer set search_path = public as $$
  select case k
    when 'itemOverrides' then public.can_edit('inventory')
    when 'customItems'   then public.can_edit('inventory')
    when 'rules'         then public.can_edit('rules')
    when 'vehicles'      then public.can_edit('fleet')
    when 'sessions'      then public.can_edit('load')
    when 'settings'      then public.can_edit('load')
    when 'eventOptions'  then public.can_edit('events') or public.can_edit('rentals')
    when 'offerSettings' then public.can_edit('offers')
    when 'offerPrices'   then public.can_edit('offers')
    else public.is_admin()
  end
$$;

-- ---------- pasiūlymai ----------
create table if not exists public.offers (
  id          uuid primary key default gen_random_uuid(),
  title       text not null default '',
  client      text not null default '',
  offer_date  date,
  status      text not null default 'draft' check (status in ('draft','final')),
  data        jsonb not null default '{}'::jsonb,
  total       numeric(12,2) not null default 0,
  job_id      uuid,
  created_by  uuid default auth.uid() references auth.users(id) on delete set null,
  updated_by  text,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists offers_updated_idx on public.offers (updated_at desc);

alter table public.offers enable row level security;
drop policy if exists "view offers" on public.offers;
create policy "view offers" on public.offers for select to authenticated using (public.can_view('offers'));
drop policy if exists "edit offers" on public.offers;
create policy "edit offers" on public.offers for all to authenticated
  using (public.can_edit('offers')) with check (public.can_edit('offers'));

-- ---------- projektai ----------
create table if not exists public.jobs (
  id          uuid primary key default gen_random_uuid(),
  title       text not null default '',
  client      text not null default '',
  location    text not null default '',
  job_date    date,
  offer_id    uuid references public.offers(id) on delete set null,
  pdf_path    text,
  notes       text not null default '',
  created_by  uuid default auth.uid() references auth.users(id) on delete set null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists jobs_date_idx on public.jobs (job_date);

alter table public.jobs enable row level security;
drop policy if exists "view jobs" on public.jobs;
create policy "view jobs" on public.jobs for select to authenticated using (public.can_view('jobs'));
drop policy if exists "add jobs" on public.jobs;
create policy "add jobs" on public.jobs for insert to authenticated with check (public.can_edit('offers') or public.can_edit('jobs'));
drop policy if exists "change jobs" on public.jobs;
create policy "change jobs" on public.jobs for update to authenticated
  using (public.can_edit('offers') or public.can_edit('jobs')) with check (public.can_edit('offers') or public.can_edit('jobs'));
drop policy if exists "delete jobs" on public.jobs;
create policy "delete jobs" on public.jobs for delete to authenticated using (public.can_edit('jobs'));

-- ---------- projektų PDF ----------
insert into storage.buckets (id, name, public) values ('job-files', 'job-files', false) on conflict (id) do nothing;
drop policy if exists "job files view" on storage.objects;
create policy "job files view" on storage.objects
  for select to authenticated using (bucket_id = 'job-files' and public.can_view('jobs'));
drop policy if exists "job files add" on storage.objects;
create policy "job files add" on storage.objects
  for insert to authenticated with check (bucket_id = 'job-files' and (public.can_edit('offers') or public.can_edit('jobs')));
drop policy if exists "job files change" on storage.objects;
create policy "job files change" on storage.objects
  for update to authenticated using (bucket_id = 'job-files' and (public.can_edit('offers') or public.can_edit('jobs')));
drop policy if exists "job files delete" on storage.objects;
create policy "job files delete" on storage.objects
  for delete to authenticated using (bucket_id = 'job-files' and (public.can_edit('offers') or public.can_edit('jobs')));


-- >>>>>>>>>> chat_slack.sql
-- ============================================================
-- Chatas kaip Slack:
--  * kanalai: vieši (# — mato ir gali prisijungti visi) ir privatūs (🔒)
--  * gijos (atsakymai į žinutę), „taip pat siųsti į kanalą“
--  * žinučių redagavimas, @paminėjimai (<@id> tekste)
--  * „Vėliau“ — išsaugotos žinutės
--  * Veikla (paminėjimai, atsakymai gijose, reakcijos) ir Failai
-- Paleisti PO chat_files.sql. Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- kanalai ----------
alter table public.conversations drop constraint if exists conversations_kind_check;
alter table public.conversations add constraint conversations_kind_check
  check (kind in ('general','direct','group','channel'));
alter table public.conversations add column if not exists topic       text not null default '';
alter table public.conversations add column if not exists is_private  boolean not null default true;
alter table public.conversations add column if not exists archived_at timestamptz;
update public.conversations set is_private = false where kind = 'general' and is_private;

-- viešus kanalus mato visi, kas naudojasi chatu
create or replace function public.is_conv_member(cid uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select public.is_approved() and public.user_can_chat(auth.uid()) and (
    exists (select 1 from public.conversations c where c.id = cid and (c.kind = 'general' or (c.kind = 'channel' and not c.is_private)))
    or exists (select 1 from public.conversation_members m where m.conversation_id = cid and m.user_id = auth.uid())
  )
$$;

drop policy if exists "join general" on public.conversation_members;
drop policy if exists "join public channels" on public.conversation_members;
create policy "join public channels" on public.conversation_members
  for insert to authenticated with check (
    user_id = auth.uid() and public.is_approved() and public.user_can_chat(auth.uid())
    and exists (select 1 from public.conversations c where c.id = conversation_id
                and (c.kind = 'general' or (c.kind = 'channel' and not c.is_private))));

drop policy if exists "rename own group" on public.conversations;
drop policy if exists "edit channel" on public.conversations;
create policy "edit channel" on public.conversations
  for update to authenticated using (kind in ('group','channel') and public.is_conv_member(id))
  with check (kind in ('group','channel'));

-- ---------- gijos ir redagavimas ----------
alter table public.messages add column if not exists parent_id    uuid references public.messages(id) on delete cascade;
alter table public.messages add column if not exists also_channel boolean not null default false;
alter table public.messages add column if not exists edited_at    timestamptz;
create index if not exists messages_parent_idx on public.messages (parent_id) where parent_id is not null;

-- atsakymas gijoje pokalbio sąraše į viršų nekelia (nebent „taip pat į kanalą“)
create or replace function public.messages_touch_conv() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if new.parent_id is null or new.also_channel then
    update public.conversations set last_message_at = new.created_at where id = new.conversation_id;
  end if;
  return new;
end $$;

-- ---------- „Vėliau“ ----------
create table if not exists public.message_saves (
  user_id    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  message_id uuid not null references public.messages(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, message_id)
);
alter table public.message_saves enable row level security;
drop policy if exists "own saves" on public.message_saves;
create policy "own saves" on public.message_saves
  for select to authenticated using (user_id = auth.uid());
drop policy if exists "add own save" on public.message_saves;
create policy "add own save" on public.message_saves
  for insert to authenticated with check (user_id = auth.uid() and public.can_see_message(message_id));
drop policy if exists "remove own save" on public.message_saves;
create policy "remove own save" on public.message_saves
  for delete to authenticated using (user_id = auth.uid());

-- ---------- kanalų valdymas ----------
create or replace function public.chat_channel_create(p_name text, p_topic text, p_private boolean, member_ids uuid[])
  returns uuid language plpgsql security definer set search_path = public as $$
declare cid uuid; nm text := lower(regexp_replace(trim(coalesce(p_name,'')), '\s+', '-', 'g'));
begin
  if not public.is_approved() or not public.user_can_chat(auth.uid()) then raise exception 'Nėra prieigos prie chato.'; end if;
  if nm = '' then raise exception 'Įrašyk kanalo pavadinimą.'; end if;
  if exists (select 1 from public.conversations where kind in ('channel','group') and lower(title) = nm and archived_at is null) then
    raise exception 'Kanalas „%“ jau yra.', nm;
  end if;
  insert into public.conversations (kind, title, topic, is_private, created_by)
  values ('channel', nm, coalesce(p_topic,''), coalesce(p_private,false), auth.uid()) returning id into cid;
  insert into public.conversation_members (conversation_id, user_id)
  select cid, p.id from public.profiles p
   where (p.id = auth.uid() or p.id = any(coalesce(member_ids,'{}'))) and public.user_can_chat(p.id)
  on conflict do nothing;
  return cid;
end $$;
grant execute on function public.chat_channel_create(text, text, boolean, uuid[]) to authenticated;

-- nariai pridedami ir į kanalus
create or replace function public.chat_group_add(cid uuid, member_ids uuid[]) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.conversations where id = cid and kind in ('group','channel')) or not public.is_conv_member(cid) then
    raise exception 'Nėra prieigos.';
  end if;
  insert into public.conversation_members (conversation_id, user_id)
  select cid, p.id from public.profiles p
   where p.id = any(member_ids) and public.user_can_chat(p.id)
  on conflict do nothing;
end $$;

-- archyvuoti / grąžinti — kūrėjas arba Admin
create or replace function public.chat_channel_archive(cid uuid, p_archive boolean) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.conversations c where c.id = cid and c.kind in ('group','channel')
                 and (c.created_by = auth.uid() or public.is_admin())) then
    raise exception 'Archyvuoti gali tik kanalo kūrėjas arba administratorius.';
  end if;
  update public.conversations set archived_at = case when p_archive then now() else null end where id = cid;
end $$;
grant execute on function public.chat_channel_archive(uuid, boolean) to authenticated;

-- ištrinti — kūrėjas arba Admin (ir kanalams)
create or replace function public.chat_group_delete(cid uuid) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.conversations c where c.id = cid and c.kind in ('group','channel')
                 and (c.created_by = auth.uid() or public.is_admin())) then
    raise exception 'Ištrinti gali tik kanalo kūrėjas arba administratorius.';
  end if;
  delete from public.conversations where id = cid;
end $$;

-- visi kanalai naršymui
create or replace function public.chat_channels_browse() returns table (
  id uuid, kind text, title text, topic text, is_private boolean, archived_at timestamptz,
  created_by uuid, members int, joined boolean, last_message_at timestamptz)
  language sql stable security definer set search_path = public as $$
  select c.id, c.kind, c.title, c.topic, c.is_private, c.archived_at, c.created_by,
         (select count(*)::int from public.conversation_members m where m.conversation_id = c.id),
         c.kind = 'general' or exists (select 1 from public.conversation_members m where m.conversation_id = c.id and m.user_id = auth.uid()),
         c.last_message_at
  from public.conversations c
  where c.kind in ('general','channel','group') and public.is_conv_member(c.id)
  order by (c.kind = 'general') desc, c.title
$$;
grant execute on function public.chat_channels_browse() to authenticated;

-- ---------- pokalbių sąrašas ----------
drop function if exists public.chat_overview();
create function public.chat_overview() returns table (
  id uuid, kind text, title text, last_message_at timestamptz, members uuid[],
  last_body text, last_sender uuid, last_attachments int, unread int, created_by uuid, last_att_kind text,
  topic text, is_private boolean, archived_at timestamptz)
  language sql stable security definer set search_path = public as $$
  select c.id, c.kind, c.title, c.last_message_at,
         coalesce((select array_agg(m.user_id) from public.conversation_members m where m.conversation_id = c.id), '{}'),
         lm.body, lm.sender_id, coalesce(jsonb_array_length(lm.attachments), 0),
         (select count(*)::int from public.messages x
           where x.conversation_id = c.id and x.deleted_at is null and x.sender_id <> auth.uid()
             and (x.parent_id is null or x.also_channel)
             and x.created_at > coalesce((select m.last_read_at from public.conversation_members m
                                          where m.conversation_id = c.id and m.user_id = auth.uid()), now() - interval '7 days')),
         c.created_by,
         lm.attachments -> 0 ->> 'type',
         c.topic, c.is_private, c.archived_at
  from public.conversations c
  left join lateral (select body, sender_id, attachments from public.messages x
                      where x.conversation_id = c.id and x.deleted_at is null and (x.parent_id is null or x.also_channel)
                      order by x.created_at desc limit 1) lm on true
  where public.is_conv_member(c.id)
    and (c.kind = 'general' or exists (select 1 from public.conversation_members m where m.conversation_id = c.id and m.user_id = auth.uid()))
  order by (c.kind = 'general') desc, c.last_message_at desc
$$;
grant execute on function public.chat_overview() to authenticated;

-- ---------- Veikla: paminėjimai, atsakymai gijose, reakcijos ----------
create or replace function public.chat_activity(p_limit int default 80) returns table (
  kind text, message_id uuid, conversation_id uuid, parent_id uuid, actor uuid, body text, emoji text, created_at timestamptz)
  language sql stable security definer set search_path = public as $$
  select * from (
    select 'mention'::text, m.id, m.conversation_id, m.parent_id, m.sender_id, m.body, null::text, m.created_at
      from public.messages m
     where m.deleted_at is null and m.sender_id <> auth.uid()
       and m.body like '%<@' || auth.uid()::text || '>%'
       and public.is_conv_member(m.conversation_id)
    union all
    select 'thread', r.id, r.conversation_id, r.parent_id, r.sender_id, r.body, null, r.created_at
      from public.messages r
     where r.parent_id is not null and r.deleted_at is null and r.sender_id <> auth.uid()
       and r.body not like '%<@' || auth.uid()::text || '>%'
       and (exists (select 1 from public.messages p where p.id = r.parent_id and p.sender_id = auth.uid())
            or exists (select 1 from public.messages o where o.parent_id = r.parent_id and o.sender_id = auth.uid()))
       and public.is_conv_member(r.conversation_id)
    union all
    select 'reaction', m.id, m.conversation_id, m.parent_id, x.user_id, m.body, x.emoji, x.created_at
      from public.message_reactions x join public.messages m on m.id = x.message_id
     where m.sender_id = auth.uid() and x.user_id <> auth.uid() and m.deleted_at is null
  ) a
  order by 8 desc
  limit greatest(1, least(coalesce(p_limit, 80), 300))
$$;
grant execute on function public.chat_activity(int) to authenticated;

-- ---------- Failai ----------
drop function if exists public.chat_files(int);
create function public.chat_files(p_limit int default 300) returns table (
  message_id uuid, conversation_id uuid, parent_id uuid, also_channel boolean, sender_id uuid, attachments jsonb, body text, created_at timestamptz)
  language sql stable security definer set search_path = public as $$
  select m.id, m.conversation_id, m.parent_id, m.also_channel, m.sender_id, m.attachments, m.body, m.created_at
    from public.messages m
   where m.deleted_at is null and jsonb_array_length(m.attachments) > 0
     and public.is_conv_member(m.conversation_id)
   order by m.created_at desc
   limit greatest(1, least(coalesce(p_limit, 300), 1000))
$$;
grant execute on function public.chat_files(int) to authenticated;


-- >>>>>>>>>> calls.sql
-- ============================================================
-- Vaizdo skambučiai chate (Google Meet arba Daily.co):
--  * calls           — skambutis pokalbyje (kas skambina, Meet nuoroda)
--  * call_responses  — kiekvieno nario atsakymas: priėmė / atmetė
--  * google_meet_auth — prijungtos Google paskyros raktas (užšifruotas);
--    jį mato tik serverio funkcija „meet“, programėlė — ne.
-- Paleisti PO chat_slack.sql. Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.calls (
  id              uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  created_by      uuid not null default auth.uid() references auth.users(id) on delete cascade,
  meet_url        text not null,
  created_at      timestamptz not null default now(),
  ended_at        timestamptz
);
-- vaizdo skambučio paslauga: Google Meet (atskiras langas) arba Daily.co (chate)
alter table public.calls add column if not exists provider text not null default 'meet';
alter table public.calls add column if not exists room text;
alter table public.calls drop constraint if exists calls_meet_url_check;
alter table public.calls drop constraint if exists calls_url_check;
alter table public.calls add constraint calls_url_check check (
  (provider = 'meet' and meet_url ~ '^https://meet\.google\.com/[a-z0-9-]+$')
  or (provider = 'daily' and meet_url ~ '^https://[a-z0-9-]+\.daily\.co/[A-Za-z0-9_-]+$'));
alter table public.calls drop constraint if exists calls_provider_check;
alter table public.calls add constraint calls_provider_check check (provider in ('meet','daily'));
create index if not exists calls_conv_idx on public.calls (conversation_id, created_at desc);

alter table public.calls enable row level security;
drop policy if exists "see calls" on public.calls;
create policy "see calls" on public.calls
  for select to authenticated using (public.is_conv_member(conversation_id));
drop policy if exists "start call" on public.calls;
create policy "start call" on public.calls
  for insert to authenticated with check (
    -- Daily kambarius kuria tik serverio funkcija „meet“ (ji tikrina narystę)
    created_by = auth.uid() and provider = 'meet' and public.is_conv_member(conversation_id)
    and (exists (select 1 from public.conversations c where c.id = conversation_id and c.kind = 'general')
         or exists (select 1 from public.conversation_members m where m.conversation_id = calls.conversation_id and m.user_id = auth.uid())));
drop policy if exists "end own call" on public.calls;
create policy "end own call" on public.calls
  for update to authenticated using (created_by = auth.uid()) with check (created_by = auth.uid());
-- skambučio kūrėjas gali tik jį užbaigti (nuorodos ar kambario pakeisti negalima)
revoke update on public.calls from authenticated;
grant update (ended_at) on public.calls to authenticated;

create table if not exists public.call_responses (
  call_id    uuid not null references public.calls(id) on delete cascade,
  user_id    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  status     text not null check (status in ('accepted','declined')),
  created_at timestamptz not null default now(),
  primary key (call_id, user_id)
);
alter table public.call_responses enable row level security;
drop policy if exists "see call answers" on public.call_responses;
create policy "see call answers" on public.call_responses
  for select to authenticated using (
    exists (select 1 from public.calls c where c.id = call_id and public.is_conv_member(c.conversation_id)));
drop policy if exists "answer call" on public.call_responses;
create policy "answer call" on public.call_responses
  for insert to authenticated with check (
    user_id = auth.uid()
    and exists (select 1 from public.calls c where c.id = call_id and public.is_conv_member(c.conversation_id)));
drop policy if exists "change answer" on public.call_responses;
create policy "change answer" on public.call_responses
  for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- Google paskyra: RLS įjungta be taisyklių — pasiekia tik serverio funkcija
create table if not exists public.google_meet_auth (
  id            int primary key default 1 check (id = 1),
  refresh_token text not null,
  email         text not null default '',
  connected_by  uuid references auth.users(id) on delete set null,
  connected_at  timestamptz not null default now()
);
alter table public.google_meet_auth enable row level security;

-- skambučiai ir atsakymai ateina realiu laiku
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'calls') then
      execute 'alter publication supabase_realtime add table public.calls';
    end if;
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'call_responses') then
      execute 'alter publication supabase_realtime add table public.call_responses';
    end if;
  end if;
end $$;


-- >>>>>>>>>> handovers.sql
-- ============================================================
-- Įrangos nuotraukos ir „Išdavimai“ (įrangos išdavimas / nuoma):
--  * nauja skiltis 'handovers' — Išdavimai (Admin → teisės)
--  * handovers — po vieną eilutę kiekvienam išdavimui (kaip „Paėmimai“)
--  * saugykla 'equipment-photos' — išorės ir vidaus nuotraukos:
--      rentals/<id>/…   (paėmimų nuotraukos, teisės pagal „Paėmimai“)
--      handovers/<id>/… (išdavimų nuotraukos, teisės pagal „Išdavimai“)
-- Paleisti PO offers.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people'));

insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','handovers',true,true), ('office','handovers',true,true), ('tech','handovers',true,true),
  ('freelance','handovers',false,false), ('runner','handovers',false,false)
on conflict (role, section) do nothing;

create table if not exists public.handovers (
  id         text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);
alter table public.handovers enable row level security;
drop policy if exists "view handovers" on public.handovers;
create policy "view handovers" on public.handovers
  for select to authenticated using (public.can_view('handovers'));
drop policy if exists "edit handovers" on public.handovers;
create policy "edit handovers" on public.handovers
  for all to authenticated using (public.can_edit('handovers')) with check (public.can_edit('handovers'));

-- nuotraukos
insert into storage.buckets (id, name, public) values ('equipment-photos', 'equipment-photos', false)
on conflict (id) do nothing;

create or replace function public.equipment_photo_access(obj_name text, edit boolean) returns boolean
  language sql stable security definer set search_path = public as $$
  select case (storage.foldername(obj_name))[1]
    when 'rentals'   then case when edit then public.can_edit('rentals')   else public.can_view('rentals')   end
    when 'handovers' then case when edit then public.can_edit('handovers') else public.can_view('handovers') end
    else false end
$$;
grant execute on function public.equipment_photo_access(text, boolean) to authenticated;

drop policy if exists "equipment photos view" on storage.objects;
create policy "equipment photos view" on storage.objects
  for select to authenticated using (bucket_id = 'equipment-photos' and public.equipment_photo_access(name, false));
drop policy if exists "equipment photos add" on storage.objects;
create policy "equipment photos add" on storage.objects
  for insert to authenticated with check (bucket_id = 'equipment-photos' and public.equipment_photo_access(name, true));
drop policy if exists "equipment photos change" on storage.objects;
create policy "equipment photos change" on storage.objects
  for update to authenticated using (bucket_id = 'equipment-photos' and public.equipment_photo_access(name, true));
drop policy if exists "equipment photos delete" on storage.objects;
create policy "equipment photos delete" on storage.objects
  for delete to authenticated using (bucket_id = 'equipment-photos' and public.equipment_photo_access(name, true));


-- >>>>>>>>>> people.sql
-- ============================================================
-- Žmonės: kontaktų archyvas ir bookingas (skambučių žurnalas)
--  * nauja skiltis 'people' — Žmonės (Admin → teisės)
--  * contacts — visi turimi kontaktai (grupės, el. paštas, telefonas, adresas)
--  * contact_calls — kas, kada ir kuriai dienai skambino ir kuo baigėsi
--    (sutiko / negali / plačiau / neatsiliepė); matosi visiems, kas turi
--    prieigą, realiu laiku — kad tam pačiam žmogui tą pačią dieną
--    niekas neskambintų antrą kartą.
-- Paleisti PO handovers.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people'));

insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','people',true,true), ('office','people',true,true), ('tech','people',false,false),
  ('freelance','people',false,false), ('runner','people',false,false)
on conflict (role, section) do nothing;

create table if not exists public.contacts (
  id         text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);
alter table public.contacts enable row level security;
drop policy if exists "view contacts" on public.contacts;
create policy "view contacts" on public.contacts
  for select to authenticated using (public.can_view('people'));
drop policy if exists "edit contacts" on public.contacts;
create policy "edit contacts" on public.contacts
  for all to authenticated using (public.can_edit('people')) with check (public.can_edit('people'));

create table if not exists public.contact_calls (
  id          uuid primary key default gen_random_uuid(),
  contact_id  text not null references public.contacts(id) on delete cascade,
  for_date    date,                       -- kuriai dienai ieškomi žmonės
  event_id    text,                       -- renginys (nebūtina)
  outcome     text not null default 'calling'
              check (outcome in ('calling','sutiko','negali','placiau','neatsiliepe')),
  note        text,
  called_at   timestamptz not null default now(),
  called_by   uuid not null default auth.uid() references auth.users(id) on delete cascade,
  caller_name text
);
create index if not exists contact_calls_contact_idx on public.contact_calls (contact_id, called_at desc);
create index if not exists contact_calls_date_idx on public.contact_calls (for_date);
alter table public.contact_calls enable row level security;
drop policy if exists "view calls log" on public.contact_calls;
create policy "view calls log" on public.contact_calls
  for select to authenticated using (public.can_view('people'));
drop policy if exists "log own calls" on public.contact_calls;
create policy "log own calls" on public.contact_calls
  for insert to authenticated with check (public.can_edit('people') and called_by = auth.uid());
drop policy if exists "update own calls" on public.contact_calls;
create policy "update own calls" on public.contact_calls
  for update to authenticated using (called_by = auth.uid() and public.can_edit('people'))
  with check (called_by = auth.uid());
drop policy if exists "delete own calls" on public.contact_calls;
create policy "delete own calls" on public.contact_calls
  for delete to authenticated using (called_by = auth.uid() or public.is_admin());
-- who called and when is fixed once written; only the outcome and the note change
revoke update on public.contact_calls from authenticated;
grant update (outcome, note) on public.contact_calls to authenticated;

-- skambučiai matosi kitiems iškart
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'contact_calls') then
      execute 'alter publication supabase_realtime add table public.contact_calls';
    end if;
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'contacts') then
      execute 'alter publication supabase_realtime add table public.contacts';
    end if;
  end if;
end $$;




-- >>>>>>>>>> people2.sql
-- ============================================================
-- Žmonės 2: bookingo žymos
--  * nauja žyma „Atsisakė“ (atsisake)
--  * žymos datą (for_date) galima pakeisti – „Sutiko“ galioja iki tos dienos
--  * žymą keisti gali ją uždėjęs žmogus arba administratorius
-- Paleisti PO people.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.contact_calls drop constraint if exists contact_calls_outcome_check;
alter table public.contact_calls add constraint contact_calls_outcome_check
  check (outcome in ('calling','sutiko','atsisake','negali','placiau','neatsiliepe'));

drop policy if exists "update own calls" on public.contact_calls;
create policy "update own calls" on public.contact_calls
  for update to authenticated using ((called_by = auth.uid() or public.is_admin()) and public.can_edit('people'))
  with check (public.can_edit('people'));

-- who called and when is fixed once written; the outcome, the note and the day change
revoke update on public.contact_calls from authenticated;
grant update (outcome, note, for_date) on public.contact_calls to authenticated;


-- >>>>>>>>>> people3.sql
-- ============================================================
-- Žmonės 3: priminimai žmonėms apie užbookintas dienas
--  * booking_reminders — kam (el. paštas), kurioms dienoms, kas kiek dienų
--    ir kelintą valandą siųsti, ar papildomai priminti dieną prieš.
--  * Siunčia funkcija booking-reminders; kas valandą ją paleidžia pg_cron
--    (tas pats slaptažodis kaip automobilių priminimų — paimamas iš jų
--    užduoties, nieko įrašyti nereikia).
-- Paleisti PO people2.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.booking_reminders (
  id              uuid primary key default gen_random_uuid(),
  contact_id      text not null references public.contacts(id) on delete cascade,
  email           text not null,
  dates           date[] not null,
  every_days      int not null default 1 check (every_days between 1 and 60),
  send_hour       int not null default 9 check (send_hour between 0 and 23),
  day_before      boolean not null default true,
  message         text,
  active          boolean not null default true,
  last_sent       date,
  sent_count      int not null default 0,
  last_error      text,
  reply_to        text,
  created_by      uuid not null default auth.uid() references auth.users(id) on delete cascade,
  created_by_name text,
  created_at      timestamptz not null default now()
);
create index if not exists booking_reminders_contact_idx on public.booking_reminders (contact_id);
create index if not exists booking_reminders_active_idx on public.booking_reminders (active) where active;
alter table public.booking_reminders enable row level security;
drop policy if exists "view booking reminders" on public.booking_reminders;
create policy "view booking reminders" on public.booking_reminders
  for select to authenticated using (public.can_view('people'));
drop policy if exists "edit booking reminders" on public.booking_reminders;
create policy "edit booking reminders" on public.booking_reminders
  for all to authenticated using (public.can_edit('people')) with check (public.can_edit('people'));

-- kas valandą (5 min. po pilnos valandos) — ta pati užduotis kaip automobilių, tik kita funkcija
do $$
declare cmd text;
begin
  if not exists (select 1 from pg_extension where extname = 'pg_cron') then
    raise notice 'pg_cron neįjungtas — pirma paleisk vehicle_reminders_cron.sql';
    return;
  end if;
  select command into cmd from cron.job where jobname = 'vehicle-reminders-daily';
  if cmd is null then
    raise notice 'Nerasta automobilių priminimų užduotis (vehicle-reminders-daily) — pirma paleisk vehicle_reminders_cron.sql';
    return;
  end if;
  cmd := replace(cmd, '/functions/v1/vehicle-reminders', '/functions/v1/booking-reminders');
  if exists (select 1 from cron.job where jobname = 'booking-reminders-hourly') then
    perform cron.unschedule('booking-reminders-hourly');
  end if;
  perform cron.schedule('booking-reminders-hourly', '5 * * * *', cmd);
end $$;


-- >>>>>>>>>> people4.sql
-- ============================================================
-- Žmonės 4: žyma „Gali“ — žmogus negali prašomomis dienomis,
-- bet pasiūlė kitas (gali dirbti tą dieną).
-- Paleisti PO people2.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.contact_calls drop constraint if exists contact_calls_outcome_check;
alter table public.contact_calls add constraint contact_calls_outcome_check
  check (outcome in ('calling','sutiko','atsisake','negali','placiau','neatsiliepe','gali'));


-- >>>>>>>>>> tasks.sql
-- ============================================================
-- Užduotys: savo užduotys ir užduotys kitiems nariams
--  * tasks — užduotis: kas sukūrė, kam paskirta (assignees; tuščia = sau),
--    atsakingas (lead), terminas (due_at), priminimai (remind),
--    kas jau atliko (done: {narys: laikas}), kurie priminimai išsiųsti (sent).
--  * task_set_done(id, done) — narys pažymi „atlikta“ (tik save).
--  * senos užduotys (todos) perkeliamos į naują lentelę.
--  * priminimus kas 5 min. siunčia funkcija push-notify (pranešimas telefone
--    ir el. laiškas) — ta pati užduotis kaip automobilių priminimų, tik kita
--    funkcija; slaptažodis paimamas iš jos, nieko įrašyti nereikia.
-- Paleisti PO calendar.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.tasks (
  id          uuid primary key default gen_random_uuid(),
  title       text not null check (char_length(title) between 1 and 300),
  note        text not null default '',
  due_at      timestamptz,
  created_by  uuid not null default auth.uid() references auth.users(id) on delete cascade,
  assignees   uuid[] not null default '{}',
  lead        uuid references auth.users(id) on delete set null,
  remind      jsonb not null default '{}'::jsonb,
  done        jsonb not null default '{}'::jsonb,
  sent        jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists tasks_created_by_idx on public.tasks (created_by);
create index if not exists tasks_assignees_idx on public.tasks using gin (assignees);
create index if not exists tasks_due_idx on public.tasks (due_at);

alter table public.tasks enable row level security;
drop policy if exists "see my tasks" on public.tasks;
create policy "see my tasks" on public.tasks
  for select to authenticated
  using (created_by = auth.uid() or auth.uid() = any(assignees) or lead = auth.uid());
drop policy if exists "create tasks" on public.tasks;
create policy "create tasks" on public.tasks
  for insert to authenticated with check (created_by = auth.uid() and public.is_approved());
drop policy if exists "edit own tasks" on public.tasks;
create policy "edit own tasks" on public.tasks
  for update to authenticated using (created_by = auth.uid()) with check (created_by = auth.uid());
drop policy if exists "delete own tasks" on public.tasks;
create policy "delete own tasks" on public.tasks
  for delete to authenticated using (created_by = auth.uid());

-- „atlikta“ gali pažymėti kiekvienas, kuriam užduotis paskirta (ar atsakingas), bet tik už save
create or replace function public.task_set_done(tid uuid, is_done boolean)
returns public.tasks
language plpgsql security definer set search_path = public as $$
declare t public.tasks;
begin
  select * into t from public.tasks where id = tid;
  if t.id is null then raise exception 'Užduotis nerasta'; end if;
  if not coalesce(t.created_by = auth.uid() or auth.uid() = any(t.assignees) or t.lead = auth.uid(), false) then
    raise exception 'Ši užduotis ne tau';
  end if;
  update public.tasks
     set done = case when is_done then done || jsonb_build_object(auth.uid()::text, now())
                     else done - auth.uid()::text end,
         updated_at = now()
   where id = tid
  returning * into t;
  return t;
end $$;
revoke all on function public.task_set_done(uuid, boolean) from public;
grant execute on function public.task_set_done(uuid, boolean) to authenticated;

-- senos užduotys (todos) → naujos (tas pats id, todėl dvigubai neperkeliama)
do $$
begin
  if exists (select 1 from information_schema.tables where table_schema = 'public' and table_name = 'todos') then
    insert into public.tasks (id, title, note, due_at, created_by, remind, created_at)
    select t.id, t.title, coalesce(t.description, ''),
           case when t.due_date is null then null
                else ((t.due_date + coalesce(t.due_time, time '09:00')) at time zone 'Europe/Vilnius') end,
           t.user_id,
           case when t.due_date is null then '{}'::jsonb else '{"before":[0],"push":true}'::jsonb end,
           t.created_at
      from public.todos t
    on conflict (id) do nothing;
  end if;
end $$;

-- sąrašai atsinaujina realiu laiku
alter table public.tasks replica identity full;
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'tasks') then
    execute 'alter publication supabase_realtime add table public.tasks';
  end if;
end $$;

-- priminimai kas 5 min.
do $$
declare cmd text;
begin
  if not exists (select 1 from pg_extension where extname = 'pg_cron') then
    raise notice 'pg_cron neįjungtas — pirma paleisk vehicle_reminders_cron.sql';
    return;
  end if;
  select command into cmd from cron.job where jobname = 'vehicle-reminders-daily';
  if cmd is null then
    raise notice 'Nerasta automobilių priminimų užduotis (vehicle-reminders-daily) — pirma paleisk vehicle_reminders_cron.sql';
    return;
  end if;
  cmd := replace(cmd, '/functions/v1/vehicle-reminders', '/functions/v1/push-notify');
  if exists (select 1 from cron.job where jobname = 'task-reminders') then
    perform cron.unschedule('task-reminders');
  end if;
  perform cron.schedule('task-reminders', '*/5 * * * *', cmd);
end $$;


-- >>>>>>>>>> tasks2.sql
-- ============================================================
-- Užduotys 2: „Runner“ ir „Freelance“ lygio nariai užduočių nekuria –
-- jie tik gauna užduotis iš kitų (ir pažymi jas atliktas).
-- Paleisti PO tasks.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

drop policy if exists "create tasks" on public.tasks;
create policy "create tasks" on public.tasks
  for insert to authenticated with check (
    created_by = auth.uid() and public.is_approved()
    and coalesce(public.my_role(), '') not in ('runner', 'freelance')
  );

-- ===== feedback.sql (Klaidos / pasiūlymai) =====
-- Klaidos / pasiūlymai: anyone signed in reports a bug or suggests an idea;
-- only admins see all of them and mark them fixed / accepted / rejected.
-- The author sees their own and is told when one is resolved.

create table if not exists public.feedback (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  created_by  uuid not null default auth.uid() references auth.users(id) on delete cascade,
  kind        text not null check (kind in ('bug', 'idea')),
  text        text not null check (length(text) between 1 and 5000),
  page        text,
  meta        jsonb not null default '{}'::jsonb,     -- app version, device, recent errors
  images      jsonb not null default '[]'::jsonb,     -- small compressed screenshots (data URLs)
  status      text not null default 'new' check (status in ('new', 'progress', 'fixed', 'accepted', 'rejected')),
  admin_note  text,
  resolved_at timestamptz,
  resolved_by uuid references auth.users(id) on delete set null,
  author_seen boolean not null default true           -- false = the author has not yet seen the answer
);
create index if not exists feedback_created_by_idx on public.feedback (created_by);
create index if not exists feedback_status_idx on public.feedback (status);

alter table public.feedback enable row level security;

drop policy if exists "feedback insert" on public.feedback;
create policy "feedback insert" on public.feedback
  for insert to authenticated with check (
    created_by = auth.uid() and public.is_approved()
    and status = 'new' and admin_note is null and resolved_at is null and resolved_by is null and author_seen
    and pg_column_size(images) < 1500000
  );

drop policy if exists "feedback read" on public.feedback;
create policy "feedback read" on public.feedback
  for select to authenticated using (created_by = auth.uid() or public.is_admin());

drop policy if exists "feedback admin update" on public.feedback;
create policy "feedback admin update" on public.feedback
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "feedback admin delete" on public.feedback;
create policy "feedback admin delete" on public.feedback
  for delete to authenticated using (public.is_admin());

grant select, insert, update, delete on public.feedback to authenticated;

-- the author marks the answers as seen (they may not change anything else)
create or replace function public.feedback_seen(ids uuid[])
returns void language sql security definer set search_path = public as $$
  update public.feedback set author_seen = true
   where id = any(ids) and created_by = auth.uid();
$$;
revoke all on function public.feedback_seen(uuid[]) from public;
grant execute on function public.feedback_seen(uuid[]) to authenticated;

do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'feedback') then
    execute 'alter publication supabase_realtime add table public.feedback';
  end if;
end $$;

-- ===== offers2.sql (klientai, „Sukurti projektą“) =====
-- ============================================================
-- Pasiūlymų kūrimas: klientų duomenų bazė + nauja skiltis „Sukurti projektą“
--  * newproj — skiltis „Sukurti projektą“ (Admin → teisės)
--  * clients — klientai (iš įkeltų ankstesnių pasiūlymų ir įvesti ranka):
--    pavadinimas, įmonės / PVM kodas, adresas, kontaktinis asmuo, el. paštas,
--    telefonas; mato tie, kas mato „Pasiūlymų kūrimą“, keičia – kas jį redaguoja.
-- Realios pasiūlymų išlaidos saugomos pačiame pasiūlyme (offers.data.actual).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people','newproj'));

insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','newproj',true,true), ('office','newproj',true,false), ('tech','newproj',true,false),
  ('freelance','newproj',false,false), ('runner','newproj',false,false)
on conflict (role, section) do nothing;

create table if not exists public.clients (
  id         text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);
alter table public.clients enable row level security;
drop policy if exists "view clients" on public.clients;
create policy "view clients" on public.clients
  for select to authenticated using (public.can_view('offers'));
drop policy if exists "edit clients" on public.clients;
create policy "edit clients" on public.clients
  for all to authenticated using (public.can_edit('offers')) with check (public.can_edit('offers'));
grant select, insert, update, delete on public.clients to authenticated;

-- ===== item_prices.sql (sandėlio kainos) =====
-- ============================================================
-- Sandėlis: daiktų kainos. Mato ir keičia tik administratoriai ir
-- projektų vadovai (lygis „pm“) – kitiems lygiams duomenų bazė jų neduoda.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.item_prices (
  item_id    text primary key,
  price      numeric(12,2),
  updated_at timestamptz not null default now(),
  updated_by text
);
alter table public.item_prices enable row level security;
drop policy if exists "prices admin and pm" on public.item_prices;
create policy "prices admin and pm" on public.item_prices
  for all to authenticated
  using (public.is_admin() or coalesce(public.my_role(), '') = 'pm')
  with check (public.is_admin() or coalesce(public.my_role(), '') = 'pm');
grant select, insert, update, delete on public.item_prices to authenticated;

-- ===== invoices.sql (Admin+, Super Admin, Sąskaitos) =====
-- ============================================================
-- Admin+, Super Admin ir Sąskaitos
--  * profiles.level: 'plus' = Admin+ (admin + sąskaitų tvirtinimas),
--    'super' = Super Admin (mato viską, gali pats keisti savo lygį ir grįžti).
--    Duomenų bazėje jų role lieka 'admin', todėl visos admin teisės galioja.
--  * Admin+ lygį skirti / nuimti gali tik Admin+ ir Super Admin;
--    Super Admin lygio niekas kitas keisti negali.
--  * invoices — gautos sąskaitos (Freelance / Paslaugų / Nuomos): įkelia visi,
--    kas gali redaguoti skiltį „Sąskaitos“; mato savo įkeltas, Admin+ – visas.
--  * invoice-files — saugykla failams (kai R2 neprijungtas).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.profiles add column if not exists level text;
alter table public.profiles drop constraint if exists profiles_level_check;
alter table public.profiles add constraint profiles_level_check check (level is null or level in ('plus','super'));

create or replace function public.is_super() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select level = 'super' from public.profiles where id = auth.uid()), false)
$$;
create or replace function public.is_plus() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'admin' and level in ('plus','super') from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.is_super(), public.is_plus() to authenticated;

-- lygio ir papildomo lygio keitimo taisyklės
create or replace function public.profiles_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if old.role = 'admin' and new.role <> 'admin'
     and not exists (select 1 from public.profiles where role = 'admin' and id <> old.id) then
    raise exception 'Negalima pašalinti paskutinio administratoriaus.';
  end if;
  -- auth.uid() is null: Supabase SQL Editor or server functions (service role)
  if auth.uid() is not null and coalesce(current_setting('app.super_switch', true), '') <> '1' then
    if not public.is_admin() then
      if new.id is distinct from old.id or new.role is distinct from old.role or new.level is distinct from old.level
         or new.email is distinct from old.email or new.approved_at is distinct from old.approved_at
         or new.approved_by is distinct from old.approved_by or new.notified_at is distinct from old.notified_at then
        raise exception 'Šių profilio laukų keisti negalima.';
      end if;
    end if;
    -- Super Admin: only he himself (through super_set_role) may change him
    if old.level = 'super' and (new.role is distinct from old.role or new.level is distinct from old.level) then
      raise exception 'Super Admin lygio keisti negalima.';
    end if;
    if new.level = 'super' and old.level is distinct from 'super' then
      raise exception 'Super Admin lygio suteikti negalima.';
    end if;
    -- Admin+ is given and taken only by Admin+ / Super Admin
    if (new.level is distinct from old.level or (old.level = 'plus' and new.role is distinct from old.role)) and not public.is_plus() then
      raise exception 'Admin+ lygį skirti gali tik Admin+ arba Super Admin.';
    end if;
  end if;
  -- leaving the admin role takes Admin+ away (Super Admin keeps his mark)
  if new.role <> 'admin' and new.level = 'plus' then new.level := null; end if;
  if new.role <> old.role and old.role = 'pending' and new.role not in ('pending','blocked') then
    new.approved_at := now();
    new.approved_by := coalesce(auth.jwt() ->> 'email', new.approved_by);
  end if;
  return new;
end $$;

-- Super Admin changes his own level to try the app as another level, and back
create or replace function public.super_set_role(r text) returns text
  language plpgsql security definer set search_path = public as $$
begin
  if not public.is_super() then raise exception 'Tik Super Admin.'; end if;
  if r not in ('admin','pm','office','tech','freelance','runner') then raise exception 'Nežinomas lygis.'; end if;
  perform set_config('app.super_switch', '1', true);
  update public.profiles set role = r where id = auth.uid();
  return r;
end $$;
revoke all on function public.super_set_role(text) from public;
grant execute on function public.super_set_role(text) to authenticated;

-- the Super Admin
update public.profiles set role = 'admin', level = 'super' where lower(email) = 'rokas@eventsolutions.lt';

-- ---------- skiltis „Sąskaitos“ ----------
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people','newproj','invoices'));
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','invoices',true,true), ('office','invoices',true,true), ('tech','invoices',true,true),
  ('freelance','invoices',true,true), ('runner','invoices',false,false)
on conflict (role, section) do nothing;

create table if not exists public.invoices (
  id            uuid primary key default gen_random_uuid(),
  created_at    timestamptz not null default now(),
  created_by    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  kind          text not null check (kind in ('freelance','service','rent')),
  supplier      text,
  number        text,
  amount        numeric(12,2),
  invoice_date  date,
  due_date      date,
  note          text,
  files         jsonb not null default '[]'::jsonb,   -- [{path,name,type,size}]
  status        text not null default 'new' check (status in ('new','approved','rejected','later','sent','queued','paid')),
  decision_note text,
  decision_by   uuid references auth.users(id) on delete set null,
  decision_at   timestamptz,
  remind_at     timestamptz,
  reminded_at   timestamptz,
  sent          jsonb not null default '[]'::jsonb,   -- [{at, by, by_email, to:[], comment, token}]
  responses     jsonb not null default '[]'::jsonb,   -- [{at, who, kind:'paid'|'queued'|'reply', text}]
  uploader_seen boolean not null default true
);
create index if not exists invoices_created_by_idx on public.invoices (created_by);
create index if not exists invoices_status_idx on public.invoices (status);
alter table public.invoices enable row level security;

drop policy if exists "invoices add" on public.invoices;
create policy "invoices add" on public.invoices
  for insert to authenticated with check (
    created_by = auth.uid() and public.can_edit('invoices')
    and status = 'new' and decision_by is null and decision_at is null and sent = '[]'::jsonb and responses = '[]'::jsonb
  );
drop policy if exists "invoices read" on public.invoices;
create policy "invoices read" on public.invoices
  for select to authenticated using (created_by = auth.uid() or public.is_plus());
drop policy if exists "invoices decide" on public.invoices;
create policy "invoices decide" on public.invoices
  for update to authenticated using (public.is_plus()) with check (public.is_plus());
drop policy if exists "invoices delete" on public.invoices;
create policy "invoices delete" on public.invoices
  for delete to authenticated using (public.is_plus() or (created_by = auth.uid() and status = 'new'));
grant select, insert, update, delete on public.invoices to authenticated;

-- the uploader marks the answer as seen
create or replace function public.invoice_seen(ids uuid[]) returns void
  language sql security definer set search_path = public as $$
  update public.invoices set uploader_seen = true where id = any(ids) and created_by = auth.uid();
$$;
revoke all on function public.invoice_seen(uuid[]) from public;
grant execute on function public.invoice_seen(uuid[]) to authenticated;

do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'invoices') then
    execute 'alter publication supabase_realtime add table public.invoices';
  end if;
end $$;

-- files: <uploader id>/<invoice id>/<file>
insert into storage.buckets (id, name, public) values ('invoice-files', 'invoice-files', false) on conflict (id) do nothing;
drop policy if exists "invoice files view" on storage.objects;
create policy "invoice files view" on storage.objects
  for select to authenticated using (bucket_id = 'invoice-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_plus()));
drop policy if exists "invoice files add" on storage.objects;
create policy "invoice files add" on storage.objects
  for insert to authenticated with check (bucket_id = 'invoice-files' and (storage.foldername(name))[1] = auth.uid()::text and public.can_edit('invoices'));
drop policy if exists "invoice files delete" on storage.objects;
create policy "invoice files delete" on storage.objects
  for delete to authenticated using (bucket_id = 'invoice-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_plus()));

-- a Super Admin cannot be deleted by anyone else
create or replace function public.profiles_delete_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if old.role = 'admin' and not exists (select 1 from public.profiles where role = 'admin' and id <> old.id) then
    raise exception 'Negalima pašalinti paskutinio administratoriaus.';
  end if;
  if old.level = 'super' and auth.uid() is not null then
    raise exception 'Super Admin ištrinti negalima.';
  end if;
  return old;
end $$;

-- ===== invoices2.sql (Pirkinių rūšis) =====
-- Sąskaitos: nauja rūšis „Pirkinių“. Supabase → SQL Editor → Run.
alter table public.invoices drop constraint if exists invoices_kind_check;
alter table public.invoices add constraint invoices_kind_check check (kind in ('freelance','service','rent','purchase'));


-- ============================================================
-- „Sukurti projektą“ (Sandėlis): projektai kaip Rentman
--  * rp_projects — projektai ir šablonai (is_template = true):
--    subprojektai, laikai, įrangos grupės su daiktais iš sandėlio,
--    papildomos išlaidos, istorija — viskas stulpelyje data (jsonb)
--  * mato tie, kas mato „Sukurti projektą“, keičia — kas jį redaguoja
--  * klientų sąrašą mato ir papildo ir „Sukurti projektą“ vartotojai
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.rp_projects (
  id          text primary key,
  name        text not null default '',
  status      text not null default 'draft',
  date_from   timestamptz,
  date_to     timestamptz,
  is_template boolean not null default false,
  data        jsonb not null default '{}'::jsonb,
  created_by  uuid default auth.uid(),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  updated_by  text
);
create index if not exists rp_projects_dates on public.rp_projects (date_from, date_to);

alter table public.rp_projects enable row level security;
drop policy if exists "view rp_projects" on public.rp_projects;
create policy "view rp_projects" on public.rp_projects
  for select to authenticated using (public.can_view('newproj'));
drop policy if exists "edit rp_projects" on public.rp_projects;
create policy "edit rp_projects" on public.rp_projects
  for all to authenticated using (public.can_edit('newproj')) with check (public.can_edit('newproj'));
grant select, insert, update, delete on public.rp_projects to authenticated;

do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'rp_projects') then
    execute 'alter publication supabase_realtime add table public.rp_projects';
  end if;
end $$;

-- klientai: ir iš „Pasiūlymų kūrimo“, ir iš „Sukurti projektą“
drop policy if exists "view clients" on public.clients;
create policy "view clients" on public.clients
  for select to authenticated using (public.can_view('offers') or public.can_view('newproj'));
drop policy if exists "edit clients" on public.clients;
create policy "edit clients" on public.clients
  for all to authenticated using (public.can_edit('offers') or public.can_edit('newproj'))
  with check (public.can_edit('offers') or public.can_edit('newproj'));
