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

-- Sandėlis → Rinkiniai (app_state raktas 'bundles') keičia tas, kas redaguoja sandėlį
create or replace function public.app_state_can_edit(k text) returns boolean
  language sql stable security definer set search_path = public as $$
  select case k
    when 'itemOverrides' then public.can_edit('inventory')
    when 'customItems'   then public.can_edit('inventory')
    when 'bundles'       then public.can_edit('inventory')
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

-- Krovimas / Pasiruošimas iš vakaro → projektas: kiek pakrauta, paruošta ir koks tikras kiekis
alter table public.rp_projects add column if not exists load_state jsonb not null default '{}'::jsonb;
-- krauti ir ruošti gali ir tie, kas redaguoja Krovimą (ne tik projektus): tik šis stulpelis
create or replace function public.rp_set_load_state(pid text, st jsonb) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not (public.can_edit('load') or public.can_edit('newproj') or public.can_edit('projects')) then
    raise exception 'Nėra teisės';
  end if;
  update public.rp_projects set load_state = coalesce(st, '{}'::jsonb) where id = pid;
end $$;
revoke all on function public.rp_set_load_state(text, jsonb) from public;
grant execute on function public.rp_set_load_state(text, jsonb) to authenticated;

-- Subnuoma (app_state raktas 'subrentItems'): įveda projektus redaguojantys; matoma tik projektuose, rūšiavime, krovime
create or replace function public.app_state_can_edit(k text) returns boolean
  language sql stable security definer set search_path = public as $$
  select case k
    when 'itemOverrides' then public.can_edit('inventory')
    when 'customItems'   then public.can_edit('inventory')
    when 'bundles'       then public.can_edit('inventory')
    when 'subrentItems'  then public.can_edit('newproj') or public.can_edit('inventory')
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
-- ============================================================
-- „Inventorizacija“ (Sandėlis)
--  * stk_items    — inventorizacijos registras: skyrius (Excel lapas), grupė,
--                   pavadinimas, kiekis, komentaras, kiti Excel stulpeliai (extra),
--                   ryšys su sandėlio daiktu (item_id), archyvavimas su priežastimi
--  * stk_sessions — inventorizacijos (Excel stulpeliai ir naujos programoje):
--                   data ir suskaičiuoti kiekiai (counts: {stk_items.id: kiekis})
--  * stk_log      — kiekių keitimai, archyvavimai ir kt. su priežastimis
--                   (tik pridedama: redaguoti ar trinti negalima)
--  * mato tie, kas mato „Sandėlį“, keičia — kas jį redaguoja
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.stk_items (
  id              text primary key,
  sheet           text not null default '',
  section         text not null default '',
  name            text not null default '',
  qty             numeric,
  qty_text        text not null default '',
  comment         text not null default '',
  extra           jsonb not null default '{}'::jsonb,
  color           text not null default '',
  item_id         text,
  archived        boolean not null default false,
  archived_reason text,
  archived_at     timestamptz,
  sort            double precision not null default 0,
  sheet_sort      double precision,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  updated_by      text
);
create index if not exists stk_items_sheet on public.stk_items (sheet, sort);

create table if not exists public.stk_sessions (
  id         text primary key,
  sheet      text not null default '',
  date       date,
  label      text not null default '',
  status     text not null default 'done',
  counts     jsonb not null default '{}'::jsonb,
  notes      jsonb not null default '{}'::jsonb,
  source     text not null default 'app',
  sort       double precision not null default 0,
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  updated_by text
);
create index if not exists stk_sessions_sheet on public.stk_sessions (sheet, date);

create table if not exists public.stk_log (
  id       bigint generated always as identity primary key,
  at       timestamptz not null default now(),
  by_id    uuid default auth.uid(),
  by_name  text,
  stk_id   text,
  sheet    text,
  name     text,
  action   text not null,
  from_v   text,
  to_v     text,
  reason   text
);
create index if not exists stk_log_item on public.stk_log (stk_id, at desc);
create index if not exists stk_log_sheet on public.stk_log (sheet, at desc);

-- kiekio keitimas ir archyvavimas be priežasties neišsaugomas ir serveryje
alter table public.stk_log drop constraint if exists stk_log_reason;
alter table public.stk_log add constraint stk_log_reason
  check (action not in ('qty','warehouse_qty','archive','restore') or length(btrim(coalesce(reason,''))) >= 3);
alter table public.stk_items drop constraint if exists stk_items_archive_reason;
alter table public.stk_items add constraint stk_items_archive_reason
  check (not archived or length(btrim(coalesce(archived_reason,''))) >= 3);

alter table public.stk_items enable row level security;
drop policy if exists "view stk_items" on public.stk_items;
create policy "view stk_items" on public.stk_items
  for select to authenticated using (public.can_view('inventory'));
drop policy if exists "edit stk_items" on public.stk_items;
create policy "edit stk_items" on public.stk_items
  for all to authenticated using (public.can_edit('inventory')) with check (public.can_edit('inventory'));
grant select, insert, update, delete on public.stk_items to authenticated;

alter table public.stk_sessions enable row level security;
drop policy if exists "view stk_sessions" on public.stk_sessions;
create policy "view stk_sessions" on public.stk_sessions
  for select to authenticated using (public.can_view('inventory'));
drop policy if exists "edit stk_sessions" on public.stk_sessions;
create policy "edit stk_sessions" on public.stk_sessions
  for all to authenticated using (public.can_edit('inventory')) with check (public.can_edit('inventory'));
grant select, insert, update, delete on public.stk_sessions to authenticated;

alter table public.stk_log enable row level security;
drop policy if exists "view stk_log" on public.stk_log;
create policy "view stk_log" on public.stk_log
  for select to authenticated using (public.can_view('inventory'));
drop policy if exists "add stk_log" on public.stk_log;
create policy "add stk_log" on public.stk_log
  for insert to authenticated with check (public.can_edit('inventory'));
grant select, insert on public.stk_log to authenticated;

-- Inventorizacija v105: atskiri vienetai po modelio eilute
alter table public.stk_items add column if not exists parent_id text;
create index if not exists stk_items_parent on public.stk_items (parent_id);
-- ============================================================
-- „Notes“: asmeniniai užrašai (Užduotys, Skaičiuotuvas)
--  * vienas užrašų lapas kiekvienam žmogui ir vietai (key: 'tasks', 'calc')
--  * mato ir keičia tik pats žmogus
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.user_notes (
  id         text primary key,               -- '<user_id>:<key>'
  user_id    uuid not null default auth.uid(),
  key        text not null,
  body       text not null default '',
  updated_at timestamptz not null default now()
);
create index if not exists user_notes_user on public.user_notes (user_id);

alter table public.user_notes enable row level security;
drop policy if exists "own notes" on public.user_notes;
create policy "own notes" on public.user_notes
  for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid() and id = auth.uid()::text || ':' || key);
grant select, insert, update, delete on public.user_notes to authenticated;
-- ============================================================
-- „Games“: žaidimų rezultatai (rekordų lentelė)
--  * vienam: kiekvienas rezultatas – eilutė, lentelėje rodomas geriausias
--  * keliese: kiekviena pergalė – eilutė su score = 1 (sumuojama)
--  * mato visi prisijungę, įrašo tik savo vardu
-- Žaidimai keliese naudoja Supabase Realtime (broadcast) – lentelių nereikia.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.game_scores (
  id         bigint generated always as identity primary key,
  user_id    uuid not null default auth.uid(),
  name       text not null default '',
  game       text not null,
  score      integer not null check (score > 0 and score < 100000000),
  created_at timestamptz not null default now()
);
create index if not exists game_scores_game on public.game_scores (game, score desc);

alter table public.game_scores enable row level security;
drop policy if exists "view game_scores" on public.game_scores;
create policy "view game_scores" on public.game_scores
  for select to authenticated using (true);
drop policy if exists "add game_scores" on public.game_scores;
create policy "add game_scores" on public.game_scores
  for insert to authenticated with check (user_id = auth.uid());
grant select, insert on public.game_scores to authenticated;
-- ============================================================
-- Saugumo sustiprinimai (2026-09)
--  1. Kas įrašė – nustato serveris, ne naršyklė: žaidimų rezultatų
--     vardas, inventorizacijos istorijos autorius ir „kas keitė“ laukai
--     nebegali būti suklastoti (anksčiau juos siuntė programa).
--  2. Žaidimų rezultatai: ne dažniau kaip 30 per minutę vienam žmogui.
--  3. Pabaigoje – PATIKRINIMAS: parodo lenteles be RLS, taisykles, kurios
--     leidžia rašyti bet kam, SECURITY DEFINER funkcijas be search_path ir
--     viešas saugyklas. Tuščias rezultatas = gerai.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- vardas iš profilio (ne iš naršyklės)
create or replace function public.me_display_name() returns text
  language sql stable security definer set search_path = public as $$
  select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.full_name, split_part(p.email, '@', 1), 'Narys')
  from public.profiles p where p.id = auth.uid()
$$;
grant execute on function public.me_display_name() to authenticated;

-- 1a. game_scores: savo vardu ir be šlamšto
create or replace function public.game_scores_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;               -- SQL Editor / service role
  new.user_id := auth.uid();
  new.name := coalesce(public.me_display_name(), 'Narys');
  new.created_at := now();
  if (select count(*) from public.game_scores where user_id = auth.uid() and created_at > now() - interval '1 minute') >= 30 then
    raise exception 'Per daug rezultatų per minutę.';
  end if;
  return new;
end $$;
drop trigger if exists game_scores_stamp on public.game_scores;
create trigger game_scores_stamp before insert on public.game_scores
  for each row execute function public.game_scores_stamp();

-- 1b. stk_log: autorius – prisijungęs žmogus, laikas – serverio
create or replace function public.stk_log_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  new.by_id := auth.uid();
  new.by_name := public.me_display_name();
  new.at := now();
  return new;
end $$;
drop trigger if exists stk_log_stamp on public.stk_log;
create trigger stk_log_stamp before insert on public.stk_log
  for each row execute function public.stk_log_stamp();

-- 1c. „kas keitė“ laukai
create or replace function public.stamp_updated_by() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  new.updated_by := public.me_display_name();
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists stk_items_stamp on public.stk_items;
create trigger stk_items_stamp before insert or update on public.stk_items
  for each row execute function public.stamp_updated_by();
drop trigger if exists stk_sessions_stamp on public.stk_sessions;
create trigger stk_sessions_stamp before insert or update on public.stk_sessions
  for each row execute function public.stamp_updated_by();

-- 1d. user_notes: tik savo (id visada '<savo id>:<vieta>')
create or replace function public.user_notes_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  new.user_id := auth.uid();
  new.id := auth.uid()::text || ':' || new.key;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists user_notes_stamp on public.user_notes;
create trigger user_notes_stamp before insert or update on public.user_notes
  for each row execute function public.user_notes_stamp();

-- ============================================================
-- 3. PATIKRINIMAS (tik skaito, nieko nekeičia)
-- ============================================================
select 'Lentelė be RLS' as problema, schemaname || '.' || tablename as kas
  from pg_tables where schemaname = 'public' and not rowsecurity
union all
select 'Taisyklė leidžia rašyti visiems', schemaname || '.' || tablename || ' → ' || policyname
  from pg_policies
  where schemaname = 'public' and cmd in ('INSERT','UPDATE','DELETE','ALL')
    and (coalesce(qual, '') in ('true', '') and coalesce(with_check, '') in ('true', ''))
union all
select 'Taisyklė atvira neprisijungusiems (anon)', schemaname || '.' || tablename || ' → ' || policyname
  from pg_policies where schemaname = 'public' and ('anon' = any(roles) or 'public' = any(roles))
union all
select 'SECURITY DEFINER be search_path', n.nspname || '.' || p.proname
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and p.prosecdef
    and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) c where c like 'search_path=%')
union all
select 'Vieša saugykla (failai be prisijungimo)', id from storage.buckets where public
order by 1, 2;
-- ============================================================
-- Saugumo sustiprinimai (2) – pagal security.sql patikrinimo rezultatą
--  1. Bendrinami projektai (?share=…): anksčiau neprisijungęs galėjo gauti
--     VISŲ bendrinamų projektų sąrašą. Dabar – tik vieną, žinant jo nuorodą
--     (funkcija guest_project). Programa v110+ naudoja ją.
--  2. Senos, programos nebenaudojamos lentelės (custom_items,
--     inventory_overrides, packing_rules, sessions_log, vehicles):
--     taisyklė „org members full access“ pakeičiama „tik administratoriai“.
--     Duomenys lieka.
--  3. Sena funkcija guest_update_qty: nustatomas search_path, neprisijungusiems
--     kviesti draudžiama.
-- Pabaigoje – tas pats patikrinimas. Tuščias rezultatas = gerai.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- 1. bendrinamas projektas tik pagal nuorodą
create or replace function public.guest_project(tok text) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'project', to_jsonb(p),
    'items', coalesce((select jsonb_agg(to_jsonb(i) order by i.created_at) from public.project_items i where i.project_id = p.id), '[]'::jsonb))
  from public.projects p
  where p.share_enabled = true and coalesce(tok, '') <> '' and p.share_token::text = tok
  limit 1
$$;
revoke all on function public.guest_project(text) from public;
grant execute on function public.guest_project(text) to anon, authenticated;
drop policy if exists "public shared projects" on public.projects;
drop policy if exists "public shared project items" on public.project_items;

-- 2. senos lentelės – tik administratoriams
do $$
declare t text;
begin
  foreach t in array array['custom_items','inventory_overrides','packing_rules','sessions_log','vehicles'] loop
    if to_regclass('public.' || t) is not null then
      execute format('alter table public.%I enable row level security', t);
      execute format('drop policy if exists %I on public.%I', 'org members full access', t);
      execute format('drop policy if exists %I on public.%I', 'admins only (old table)', t);
      execute format('create policy %I on public.%I for all to authenticated using (public.is_admin()) with check (public.is_admin())', 'admins only (old table)', t);
      execute format('revoke all on public.%I from anon', t);
    end if;
  end loop;
end $$;

-- 3. sena funkcija guest_update_qty
do $$
declare f record;
begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'public' and p.proname = 'guest_update_qty' loop
    execute format('alter function %s set search_path = public', f.sig);
    execute format('revoke execute on function %s from public, anon', f.sig);
  end loop;
end $$;

-- ============================================================
-- PATIKRINIMAS (tik skaito)
-- ============================================================
select 'Lentelė be RLS' as problema, schemaname || '.' || tablename as kas
  from pg_tables where schemaname = 'public' and not rowsecurity
union all
select 'Taisyklė leidžia rašyti visiems', schemaname || '.' || tablename || ' → ' || policyname
  from pg_policies
  where schemaname = 'public' and cmd in ('INSERT','UPDATE','DELETE','ALL')
    and (coalesce(qual, '') in ('true', '') and coalesce(with_check, '') in ('true', ''))
union all
select 'Taisyklė atvira neprisijungusiems (anon)', schemaname || '.' || tablename || ' → ' || policyname
  from pg_policies where schemaname = 'public' and ('anon' = any(roles) or 'public' = any(roles))
union all
select 'SECURITY DEFINER be search_path', n.nspname || '.' || p.proname
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and p.prosecdef
    and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) c where c like 'search_path=%')
union all
select 'Vieša saugykla (failai be prisijungimo)', id from storage.buckets where public
order by 1, 2;
-- ============================================================
-- El. paštas greičiau: laiškų sąrašas laikomas duomenų bazėje
--  * mail_index – kiekvieno laiško antraštė (nuo ko, tema, data, žymos);
--    programa sąrašą skaito iš čia – iš karto ir surikiuotą pagal datą
--  * mail_sync  – kiekvieno aplanko sinchronizavimo būsena
--  * pildo tik „mail“ funkcija (serveris), kas minutę per pg_cron ir kai
--    kas nors atsidaro aplanką; kiekvienas mato TIK SAVO laiškus
--  * nauji laiškai į programą atkeliauja per Realtime
-- Reikia: „mail“ funkcija v11+ (supabase functions deploy mail).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.mail_index (
  user_id     uuid not null references auth.users(id) on delete cascade,
  folder      text not null,
  uid         bigint not null,
  date        timestamptz,
  subject     text not null default '',
  from_addr   jsonb not null default '[]'::jsonb,
  to_addr     jsonb not null default '[]'::jsonb,
  seen        boolean not null default false,
  answered    boolean not null default false,
  flagged     boolean not null default false,
  attachments boolean not null default false,
  size        integer,
  updated_at  timestamptz not null default now(),
  primary key (user_id, folder, uid)
);
create index if not exists mail_index_list on public.mail_index (user_id, folder, date desc nulls last, uid desc);
create index if not exists mail_index_unseen on public.mail_index (user_id, folder) where not seen;

create table if not exists public.mail_sync (
  user_id     uuid not null references auth.users(id) on delete cascade,
  folder      text not null,
  uidvalidity text,
  modseq      text,
  total       integer,
  unseen      integer,
  remaining   integer,
  synced_at   timestamptz,
  primary key (user_id, folder)
);

-- kiekvienas mato tik savo; rašo tik serverio funkcija (service role)
alter table public.mail_index enable row level security;
alter table public.mail_sync  enable row level security;
drop policy if exists "own mail index" on public.mail_index;
create policy "own mail index" on public.mail_index for select to authenticated using (user_id = auth.uid());
drop policy if exists "own mail sync" on public.mail_sync;
create policy "own mail sync" on public.mail_sync for select to authenticated using (user_id = auth.uid());
revoke all on public.mail_index, public.mail_sync from anon;
revoke insert, update, delete on public.mail_index, public.mail_sync from authenticated;
grant select on public.mail_index, public.mail_sync to authenticated;

-- atsijungus nuo pašto – ir sąrašas ištrinamas
create or replace function public.mail_index_cleanup() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  delete from public.mail_index where user_id = old.user_id;
  delete from public.mail_sync  where user_id = old.user_id;
  return old;
end $$;
drop trigger if exists mail_index_cleanup on public.mail_accounts;
create trigger mail_index_cleanup after delete on public.mail_accounts
  for each row execute function public.mail_index_cleanup();

-- nauji laiškai į atidarytą programą be atnaujinimo
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'mail_index') then
    execute 'alter publication supabase_realtime add table public.mail_index';
  end if;
end $$;

-- kas minutę: visų prijungtų dėžučių Inbox (Išsiųsti – kas 5 min.)
-- naudojamas tas pats CRON_SECRET kaip automobilių priminimams
create extension if not exists pg_cron;
create extension if not exists pg_net;
do $$
declare secret text;
begin
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
    from cron.job where jobname = 'vehicle-reminders-daily';
  if secret is null or secret = 'PAKEISK_SLAPTAZODI' then
    raise notice 'Nerastas CRON_SECRET (vehicle-reminders-daily): kas minutę sinchronizuojama nebus, sąrašas atsinaujins, kai atsidarysi paštą.';
    return;
  end if;
  perform cron.unschedule(jobid) from cron.job where jobname = 'mail-sync';
  perform cron.schedule('mail-sync', '* * * * *', format($job$
    select net.http_post(
      url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/mail',
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', %L),
      body    := '{"action":"sync_all"}'::jsonb,
      timeout_milliseconds := 110000
    );
  $job$, secret));
end $$;
-- ============================================================
-- „Įranga“: pažeista / sugadinta ir dingusi įranga
--  * kind 'damage': state 'usable' (pažeista, bet naudojama – kiekis
--    nesikeičia) arba 'broken' (negalima naudoti – išimama iš sandėlio,
--    kol status nepasikeičia į 'fixed');
--    assignee – kas atsakingas už taisymą (jam sukuriama užduotis)
--  * kind 'lost': kas dingo, kada pastebėta, kur galimai; members – kas
--    pažymėti (gauna pranešimą); išimama iš sandėlio, kol 'found'
--  * status: open | fixed | found | written_off (nurašyta – lieka išimta)
--  * mato ir praneša tie, kas mato „Sandėlį“; tvarko – kas jį redaguoja,
--    taip pat pranešęs, atsakingas ir pažymėti nariai
--  * nuotraukos: 'equipment-photos' saugykla, gear/<id>/…
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.gear_issues (
  id               uuid primary key default gen_random_uuid(),
  kind             text not null check (kind in ('damage','lost')),
  item_id          text,
  item_name        text not null default '',
  qty              integer not null default 1 check (qty > 0 and qty < 100000),
  state            text not null default 'usable' check (state in ('usable','broken','lost')),
  status           text not null default 'open' check (status in ('open','fixed','found','written_off')),
  description      text not null default '',
  place            text,
  noticed_at       date,
  event_name       text,
  photos           jsonb not null default '[]'::jsonb,
  assignee         uuid references auth.users(id) on delete set null,
  members          uuid[] not null default '{}',
  task_id          uuid,
  created_by       uuid not null default auth.uid(),
  created_by_name  text,
  created_at       timestamptz not null default now(),
  resolved_at      timestamptz,
  resolved_by_name text,
  resolution       text,
  updated_at       timestamptz not null default now()
);
create index if not exists gear_issues_open on public.gear_issues (status, item_id);

alter table public.gear_issues enable row level security;
drop policy if exists "view gear issues" on public.gear_issues;
create policy "view gear issues" on public.gear_issues for select to authenticated
  using (public.can_view('inventory') or created_by = auth.uid() or assignee = auth.uid() or auth.uid() = any(members));
drop policy if exists "report gear issues" on public.gear_issues;
create policy "report gear issues" on public.gear_issues for insert to authenticated
  with check (public.can_view('inventory') and created_by = auth.uid());
drop policy if exists "change gear issues" on public.gear_issues;
create policy "change gear issues" on public.gear_issues for update to authenticated
  using (public.can_edit('inventory') or created_by = auth.uid() or assignee = auth.uid() or auth.uid() = any(members))
  with check (public.can_edit('inventory') or created_by = auth.uid() or assignee = auth.uid() or auth.uid() = any(members));
drop policy if exists "delete gear issues" on public.gear_issues;
create policy "delete gear issues" on public.gear_issues for delete to authenticated
  using (public.can_edit('inventory'));
grant select, insert, update, delete on public.gear_issues to authenticated;

-- pranešęs žmogus ir laikas – nustato serveris
create or replace function public.gear_issues_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  if tg_op = 'INSERT' then
    new.created_by := auth.uid();
    new.created_at := now();
    new.created_by_name := coalesce((select nullif(trim(concat_ws(' ', p.first_name, p.last_name)), '') from public.profiles p where p.id = auth.uid()), new.created_by_name);
  else
    new.created_by := old.created_by; new.created_at := old.created_at; new.created_by_name := old.created_by_name;
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists gear_issues_stamp on public.gear_issues;
create trigger gear_issues_stamp before insert or update on public.gear_issues
  for each row execute function public.gear_issues_stamp();

-- pokyčiai iš karto visiems (Realtime)
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'gear_issues') then
    execute 'alter publication supabase_realtime add table public.gear_issues';
  end if;
end $$;

-- nuotraukos: ta pati 'equipment-photos' saugykla, aplankas gear/
create or replace function public.equipment_photo_access(obj_name text, edit boolean) returns boolean
  language sql stable security definer set search_path = public as $$
  select case (storage.foldername(obj_name))[1]
    when 'rentals'   then case when edit then public.can_edit('rentals')   else public.can_view('rentals')   end
    when 'handovers' then case when edit then public.can_edit('handovers') else public.can_view('handovers') end
    when 'gear'      then public.can_view('inventory')
    else false end
$$;
grant execute on function public.equipment_photo_access(text, boolean) to authenticated;


-- ===== gear_writeoff.sql =====
-- ============================================================
-- „Įranga“ → Nurašyti su patvirtinimu
--  * Paspaudus „Nurašyti“ galima siųsti prašymą patvirtinti. Prašymą gauna
--    visi Admin+ nariai (role 'admin', level 'plus' arba 'super').
--    Kol vienas iš jų nepatvirtina, daiktas NEnurašomas (status lieka
--    'open', sugadintas / dingęs daiktas lieka išimtas iš sandėlio kaip buvo).
--  * Patvirtinti ar atmesti gali tik Admin+ narys ir ne tas, kuris prašė
--    (tikrina serveris); kol laukiama patvirtinimo, statuso pakeisti negalima.
--  * wo_approver – kas patvirtino / atmetė.
-- Paleisti po gear.sql ir invoices.sql (public.is_plus()).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.gear_issues
  add column if not exists wo_status          text check (wo_status in ('pending','approved','rejected')),
  add column if not exists wo_approver        uuid references auth.users(id) on delete set null,
  add column if not exists wo_requested_by    uuid,
  add column if not exists wo_requested_name  text,
  add column if not exists wo_requested_at    timestamptz,
  add column if not exists wo_note            text,
  add column if not exists wo_decided_at      timestamptz,
  add column if not exists wo_decision_note   text;
drop index if exists public.gear_issues_wo;
create index if not exists gear_issues_wo_pending on public.gear_issues (wo_status) where wo_status = 'pending';

-- Admin+ mato nurašymo prašymus net jei nemato „Sandėlio“
drop policy if exists "view gear issues" on public.gear_issues;
create policy "view gear issues" on public.gear_issues for select to authenticated
  using (public.can_view('inventory') or created_by = auth.uid() or assignee = auth.uid() or auth.uid() = any(members)
         or (wo_status is not null and public.is_plus()));

drop function if exists public.gear_wo_approver();

create or replace function public.gear_me_name() returns text
  language sql stable security definer set search_path = public as $$
  select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid()
$$;

-- nurašymo laukai keičiami tik per funkcijas žemiau
create or replace function public.gear_issues_wo_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or coalesce(current_setting('gear.wo', true), '') = '1' then return new; end if;
  if tg_op = 'INSERT' then
    new.wo_status := null; new.wo_approver := null; new.wo_requested_by := null; new.wo_requested_name := null;
    new.wo_requested_at := null; new.wo_note := null; new.wo_decided_at := null; new.wo_decision_note := null;
    return new;
  end if;
  new.wo_status := old.wo_status; new.wo_approver := old.wo_approver; new.wo_requested_by := old.wo_requested_by;
  new.wo_requested_name := old.wo_requested_name; new.wo_requested_at := old.wo_requested_at; new.wo_note := old.wo_note;
  new.wo_decided_at := old.wo_decided_at; new.wo_decision_note := old.wo_decision_note;
  if old.wo_status = 'pending' and new.status is distinct from old.status then
    raise exception 'Laukiama nurašymo patvirtinimo – statuso keisti negalima, kol prašymas neišspręstas.';
  end if;
  return new;
end $$;
drop trigger if exists gear_issues_wo_guard on public.gear_issues;
create trigger gear_issues_wo_guard before insert or update on public.gear_issues
  for each row execute function public.gear_issues_wo_guard();

-- prašymas nurašyti (tas, kas tvarko „Sandėlį“)
create or replace function public.gear_wo_request(gid uuid, note text default null) returns public.gear_issues
  language plpgsql security definer set search_path = public as $$
declare g public.gear_issues;
begin
  if not public.can_edit('inventory') then raise exception 'Nurašyti gali tik tas, kas tvarko sandėlį.'; end if;
  if not exists (select 1 from public.profiles where role = 'admin' and level in ('plus','super') and id <> auth.uid()) then
    raise exception 'Nėra Admin+ nario, kuris galėtų patvirtinti.';
  end if;
  select * into g from public.gear_issues where id = gid for update;
  if not found then raise exception 'Įrašas nerastas'; end if;
  if g.status <> 'open' then raise exception 'Įrašas jau išspręstas.'; end if;
  if g.wo_status = 'pending' then raise exception 'Prašymas jau išsiųstas.'; end if;
  perform set_config('gear.wo', '1', true);
  update public.gear_issues set wo_status = 'pending', wo_approver = null, wo_requested_by = auth.uid(),
    wo_requested_name = public.gear_me_name(), wo_requested_at = now(), wo_note = nullif(trim(note), ''),
    wo_decided_at = null, wo_decision_note = null
   where id = gid returning * into g;
  perform set_config('gear.wo', '', true);
  return g;
end $$;

-- patvirtinti / atmesti (Admin+, ne tas, kuris prašė)
create or replace function public.gear_wo_decide(gid uuid, approve boolean, note text default null) returns public.gear_issues
  language plpgsql security definer set search_path = public as $$
declare g public.gear_issues;
begin
  select * into g from public.gear_issues where id = gid for update;
  if not found then raise exception 'Įrašas nerastas'; end if;
  if g.wo_status is distinct from 'pending' then raise exception 'Šis prašymas jau išspręstas.'; end if;
  if not public.is_plus() then raise exception 'Patvirtinti gali tik Admin+ narys.'; end if;
  if g.wo_requested_by = auth.uid() then raise exception 'Savo prašymo patvirtinti negalima – patvirtina kitas Admin+ narys.'; end if;
  perform set_config('gear.wo', '1', true);
  if approve then
    update public.gear_issues set wo_status = 'approved', wo_approver = auth.uid(), wo_decided_at = now(), wo_decision_note = nullif(trim(note), ''),
      status = 'written_off', resolved_at = now(), resolved_by_name = public.gear_me_name(),
      resolution = nullif(concat_ws(' · ', nullif(trim(g.wo_note), ''), nullif(trim(note), '')), '')
     where id = gid returning * into g;
  else
    update public.gear_issues set wo_status = 'rejected', wo_approver = auth.uid(), wo_decided_at = now(), wo_decision_note = nullif(trim(note), '')
     where id = gid returning * into g;
  end if;
  perform set_config('gear.wo', '', true);
  return g;
end $$;

-- atšaukti savo prašymą
create or replace function public.gear_wo_cancel(gid uuid) returns public.gear_issues
  language plpgsql security definer set search_path = public as $$
declare g public.gear_issues;
begin
  select * into g from public.gear_issues where id = gid for update;
  if not found then raise exception 'Įrašas nerastas'; end if;
  if g.wo_status is distinct from 'pending' then raise exception 'Prašymas jau išspręstas.'; end if;
  if g.wo_requested_by is distinct from auth.uid() and not public.can_edit('inventory') then raise exception 'Atšaukti gali prašymą išsiuntęs narys.'; end if;
  perform set_config('gear.wo', '1', true);
  update public.gear_issues set wo_status = null, wo_approver = null, wo_requested_by = null, wo_requested_name = null,
    wo_requested_at = null, wo_note = null, wo_decided_at = null, wo_decision_note = null
   where id = gid returning * into g;
  perform set_config('gear.wo', '', true);
  return g;
end $$;

revoke all on function public.gear_wo_request(uuid, text) from public, anon;
revoke all on function public.gear_wo_decide(uuid, boolean, text) from public, anon;
revoke all on function public.gear_wo_cancel(uuid) from public, anon;
revoke all on function public.gear_me_name() from public, anon;
grant execute on function public.gear_wo_request(uuid, text) to authenticated;
grant execute on function public.gear_wo_decide(uuid, boolean, text) to authenticated;
grant execute on function public.gear_wo_cancel(uuid) to authenticated;
grant execute on function public.gear_me_name() to authenticated;


-- ===== gear_writeoff.sql (be „Nurašyti iš karto“) =====
-- ============================================================
-- „Įranga“ → Nurašyti su patvirtinimu
--  * Paspaudus „Nurašyti“ galima siųsti prašymą patvirtinti. Prašymą gauna
--    visi Admin+ nariai (role 'admin', level 'plus' arba 'super').
--    Kol vienas iš jų nepatvirtina, daiktas NEnurašomas (status lieka
--    'open', sugadintas / dingęs daiktas lieka išimtas iš sandėlio kaip buvo).
--  * Patvirtinti ar atmesti gali tik Admin+ narys ir ne tas, kuris prašė
--    (tikrina serveris); kol laukiama patvirtinimo, statuso pakeisti negalima.
--  * Nurašyti be patvirtinimo negalima: status 'written_off' nustatomas tik
--    patvirtinus prašymą.
--  * wo_approver – kas patvirtino / atmetė.
-- Paleisti po gear.sql ir invoices.sql (public.is_plus()).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.gear_issues
  add column if not exists wo_status          text check (wo_status in ('pending','approved','rejected')),
  add column if not exists wo_approver        uuid references auth.users(id) on delete set null,
  add column if not exists wo_requested_by    uuid,
  add column if not exists wo_requested_name  text,
  add column if not exists wo_requested_at    timestamptz,
  add column if not exists wo_note            text,
  add column if not exists wo_decided_at      timestamptz,
  add column if not exists wo_decision_note   text;
drop index if exists public.gear_issues_wo;
create index if not exists gear_issues_wo_pending on public.gear_issues (wo_status) where wo_status = 'pending';

-- Admin+ mato nurašymo prašymus net jei nemato „Sandėlio“
drop policy if exists "view gear issues" on public.gear_issues;
create policy "view gear issues" on public.gear_issues for select to authenticated
  using (public.can_view('inventory') or created_by = auth.uid() or assignee = auth.uid() or auth.uid() = any(members)
         or (wo_status is not null and public.is_plus()));

drop function if exists public.gear_wo_approver();

create or replace function public.gear_me_name() returns text
  language sql stable security definer set search_path = public as $$
  select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid()
$$;

-- nurašymo laukai keičiami tik per funkcijas žemiau
create or replace function public.gear_issues_wo_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or coalesce(current_setting('gear.wo', true), '') = '1' then return new; end if;
  if tg_op = 'INSERT' then
    new.wo_status := null; new.wo_approver := null; new.wo_requested_by := null; new.wo_requested_name := null;
    new.wo_requested_at := null; new.wo_note := null; new.wo_decided_at := null; new.wo_decision_note := null;
    if new.status = 'written_off' then raise exception 'Nurašyti galima tik su Admin+ patvirtinimu.'; end if;
    return new;
  end if;
  new.wo_status := old.wo_status; new.wo_approver := old.wo_approver; new.wo_requested_by := old.wo_requested_by;
  new.wo_requested_name := old.wo_requested_name; new.wo_requested_at := old.wo_requested_at; new.wo_note := old.wo_note;
  new.wo_decided_at := old.wo_decided_at; new.wo_decision_note := old.wo_decision_note;
  if old.wo_status = 'pending' and new.status is distinct from old.status then
    raise exception 'Laukiama nurašymo patvirtinimo – statuso keisti negalima, kol prašymas neišspręstas.';
  end if;
  if new.status = 'written_off' and old.status is distinct from 'written_off' then
    raise exception 'Nurašyti galima tik su Admin+ patvirtinimu.';
  end if;
  return new;
end $$;
drop trigger if exists gear_issues_wo_guard on public.gear_issues;
create trigger gear_issues_wo_guard before insert or update on public.gear_issues
  for each row execute function public.gear_issues_wo_guard();

-- prašymas nurašyti (tas, kas tvarko „Sandėlį“)
create or replace function public.gear_wo_request(gid uuid, note text default null) returns public.gear_issues
  language plpgsql security definer set search_path = public as $$
declare g public.gear_issues;
begin
  if not public.can_edit('inventory') then raise exception 'Nurašyti gali tik tas, kas tvarko sandėlį.'; end if;
  if not exists (select 1 from public.profiles where role = 'admin' and level in ('plus','super') and id <> auth.uid()) then
    raise exception 'Nėra Admin+ nario, kuris galėtų patvirtinti.';
  end if;
  select * into g from public.gear_issues where id = gid for update;
  if not found then raise exception 'Įrašas nerastas'; end if;
  if g.status <> 'open' then raise exception 'Įrašas jau išspręstas.'; end if;
  if g.wo_status = 'pending' then raise exception 'Prašymas jau išsiųstas.'; end if;
  perform set_config('gear.wo', '1', true);
  update public.gear_issues set wo_status = 'pending', wo_approver = null, wo_requested_by = auth.uid(),
    wo_requested_name = public.gear_me_name(), wo_requested_at = now(), wo_note = nullif(trim(note), ''),
    wo_decided_at = null, wo_decision_note = null
   where id = gid returning * into g;
  perform set_config('gear.wo', '', true);
  return g;
end $$;

-- patvirtinti / atmesti (Admin+, ne tas, kuris prašė)
create or replace function public.gear_wo_decide(gid uuid, approve boolean, note text default null) returns public.gear_issues
  language plpgsql security definer set search_path = public as $$
declare g public.gear_issues;
begin
  select * into g from public.gear_issues where id = gid for update;
  if not found then raise exception 'Įrašas nerastas'; end if;
  if g.wo_status is distinct from 'pending' then raise exception 'Šis prašymas jau išspręstas.'; end if;
  if not public.is_plus() then raise exception 'Patvirtinti gali tik Admin+ narys.'; end if;
  if g.wo_requested_by = auth.uid() then raise exception 'Savo prašymo patvirtinti negalima – patvirtina kitas Admin+ narys.'; end if;
  perform set_config('gear.wo', '1', true);
  if approve then
    update public.gear_issues set wo_status = 'approved', wo_approver = auth.uid(), wo_decided_at = now(), wo_decision_note = nullif(trim(note), ''),
      status = 'written_off', resolved_at = now(), resolved_by_name = public.gear_me_name(),
      resolution = nullif(concat_ws(' · ', nullif(trim(g.wo_note), ''), nullif(trim(note), '')), '')
     where id = gid returning * into g;
  else
    update public.gear_issues set wo_status = 'rejected', wo_approver = auth.uid(), wo_decided_at = now(), wo_decision_note = nullif(trim(note), '')
     where id = gid returning * into g;
  end if;
  perform set_config('gear.wo', '', true);
  return g;
end $$;

-- atšaukti savo prašymą
create or replace function public.gear_wo_cancel(gid uuid) returns public.gear_issues
  language plpgsql security definer set search_path = public as $$
declare g public.gear_issues;
begin
  select * into g from public.gear_issues where id = gid for update;
  if not found then raise exception 'Įrašas nerastas'; end if;
  if g.wo_status is distinct from 'pending' then raise exception 'Prašymas jau išspręstas.'; end if;
  if g.wo_requested_by is distinct from auth.uid() and not public.can_edit('inventory') then raise exception 'Atšaukti gali prašymą išsiuntęs narys.'; end if;
  perform set_config('gear.wo', '1', true);
  update public.gear_issues set wo_status = null, wo_approver = null, wo_requested_by = null, wo_requested_name = null,
    wo_requested_at = null, wo_note = null, wo_decided_at = null, wo_decision_note = null
   where id = gid returning * into g;
  perform set_config('gear.wo', '', true);
  return g;
end $$;

revoke all on function public.gear_wo_request(uuid, text) from public, anon;
revoke all on function public.gear_wo_decide(uuid, boolean, text) from public, anon;
revoke all on function public.gear_wo_cancel(uuid) from public, anon;
revoke all on function public.gear_me_name() from public, anon;
grant execute on function public.gear_wo_request(uuid, text) to authenticated;
grant execute on function public.gear_wo_decide(uuid, boolean, text) to authenticated;
grant execute on function public.gear_wo_cancel(uuid) to authenticated;
grant execute on function public.gear_me_name() to authenticated;


-- ===== leave.sql =====
-- ============================================================
-- Profilis → Prašymai: laisvos dienos ir atostogos
--  * kind 'dayoff'  – konkrečios dienos (days), date_from/date_to = pirma/paskutinė
--  * kind 'vacation' – laikotarpis date_from … date_to
--  * Prašymą mato jį pateikęs narys, „office“ nariai ir Admin+;
--    patvirtinti / atmesti gali tik Admin+ (ne savo prašymo).
--  * Patvirtintos dienos (be priežasčių) visiems prisijungusiems grąžina
--    leave_busy() – pagal jas renginiuose neleidžiama įrašyti nario.
-- Paleisti po invoices.sql (public.is_plus()). Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.leave_requests (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid not null default auth.uid() references auth.users(id) on delete cascade,
  user_name        text,
  kind             text not null check (kind in ('dayoff','vacation')),
  days             date[] not null default '{}',
  date_from        date not null,
  date_to          date not null,
  reason           text not null default '',
  status           text not null default 'pending' check (status in ('pending','approved','rejected','cancelled')),
  decided_by       uuid references auth.users(id) on delete set null,
  decided_by_name  text,
  decided_at       timestamptz,
  decision_note    text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  check (date_to >= date_from),
  check (date_to - date_from <= 366),
  check (kind <> 'dayoff' or cardinality(days) between 1 and 60)
);
create index if not exists leave_requests_user on public.leave_requests (user_id, created_at desc);
create index if not exists leave_requests_open on public.leave_requests (status, date_to);

-- Admin+ (tas pats kaip invoices.sql)
create or replace function public.is_plus() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'admin' and level in ('plus','super') from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.is_plus() to authenticated;

create or replace function public.leave_can_see_all() returns boolean
  language sql stable security definer set search_path = public as $$
  select public.is_plus() or coalesce((select role = 'office' from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.leave_can_see_all() to authenticated;

alter table public.leave_requests enable row level security;
drop policy if exists "view leave" on public.leave_requests;
create policy "view leave" on public.leave_requests for select to authenticated
  using (user_id = auth.uid() or public.leave_can_see_all());
drop policy if exists "ask leave" on public.leave_requests;
create policy "ask leave" on public.leave_requests for insert to authenticated
  with check (user_id = auth.uid() and public.is_approved());
-- keisti galima tik per funkcijas žemiau
drop policy if exists "change leave" on public.leave_requests;
grant select, insert on public.leave_requests to authenticated;
revoke update, delete on public.leave_requests from authenticated;

-- naujas prašymas: kas, kada, būsena 'pending' ir dienos – nustato serveris
create or replace function public.leave_requests_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or coalesce(current_setting('leave.rpc', true), '') = '1' then return new; end if;
  new.user_id := auth.uid();
  new.user_name := (select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid());
  new.status := 'pending'; new.decided_by := null; new.decided_by_name := null; new.decided_at := null; new.decision_note := null;
  new.created_at := now(); new.updated_at := now();
  new.reason := trim(coalesce(new.reason, ''));
  if new.reason = '' then raise exception 'Parašyk, kodėl prašai.'; end if;
  if new.kind = 'dayoff' then
    new.days := (select array_agg(distinct d order by d) from unnest(new.days) d);
    if new.days is null then raise exception 'Pasirink bent vieną dieną.'; end if;
    new.date_from := new.days[1]; new.date_to := new.days[array_length(new.days, 1)];
  else
    new.days := '{}';
  end if;
  if new.date_to < current_date then raise exception 'Negalima prašyti praėjusių dienų.'; end if;
  return new;
end $$;
drop trigger if exists leave_requests_stamp on public.leave_requests;
create trigger leave_requests_stamp before insert on public.leave_requests
  for each row execute function public.leave_requests_stamp();

create or replace function public.leave_me_name() returns text
  language sql stable security definer set search_path = public as $$
  select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid()
$$;

-- patvirtinti / atmesti: tik Admin+, ne savo prašymo
create or replace function public.leave_decide(rid uuid, approve boolean, note text default null) returns public.leave_requests
  language plpgsql security definer set search_path = public as $$
declare r public.leave_requests;
begin
  if not public.is_plus() then raise exception 'Patvirtinti gali tik Admin+ narys.'; end if;
  select * into r from public.leave_requests where id = rid for update;
  if not found then raise exception 'Prašymas nerastas'; end if;
  if r.status <> 'pending' then raise exception 'Šis prašymas jau išspręstas.'; end if;
  if r.user_id = auth.uid() then raise exception 'Savo prašymo patvirtinti negalima – patvirtina kitas Admin+ narys.'; end if;
  perform set_config('leave.rpc', '1', true);
  update public.leave_requests set status = case when approve then 'approved' else 'rejected' end,
    decided_by = auth.uid(), decided_by_name = public.leave_me_name(), decided_at = now(),
    decision_note = nullif(trim(note), ''), updated_at = now()
   where id = rid returning * into r;
  perform set_config('leave.rpc', '', true);
  return r;
end $$;

-- atšaukti savo prašymą (laukiantį arba patvirtintą, kol jis dar nesibaigė)
create or replace function public.leave_cancel(rid uuid) returns public.leave_requests
  language plpgsql security definer set search_path = public as $$
declare r public.leave_requests;
begin
  select * into r from public.leave_requests where id = rid for update;
  if not found then raise exception 'Prašymas nerastas'; end if;
  if r.user_id <> auth.uid() and not public.is_plus() then raise exception 'Atšaukti gali tik prašymą pateikęs narys.'; end if;
  if r.status not in ('pending','approved') then raise exception 'Šio prašymo atšaukti nebegalima.'; end if;
  if r.date_to < current_date then raise exception 'Laikotarpis jau praėjęs.'; end if;
  perform set_config('leave.rpc', '1', true);
  update public.leave_requests set status = 'cancelled', updated_at = now() where id = rid returning * into r;
  perform set_config('leave.rpc', '', true);
  return r;
end $$;

-- patvirtintos laisvos dienos / atostogos (be priežasčių) – renginių tikrinimui
create or replace function public.leave_busy() returns table (user_id uuid, kind text, days date[], date_from date, date_to date)
  language sql stable security definer set search_path = public as $$
  select l.user_id, l.kind, l.days, l.date_from, l.date_to
    from public.leave_requests l
   where l.status = 'approved' and l.date_to >= current_date - 400 and public.is_approved()
$$;

revoke all on function public.leave_decide(uuid, boolean, text) from public, anon;
revoke all on function public.leave_cancel(uuid) from public, anon;
revoke all on function public.leave_busy() from public, anon;
revoke all on function public.leave_me_name() from public, anon;
grant execute on function public.leave_decide(uuid, boolean, text) to authenticated;
grant execute on function public.leave_cancel(uuid) to authenticated;
grant execute on function public.leave_busy() to authenticated;
grant execute on function public.leave_me_name() to authenticated;

-- pokyčiai iš karto (Realtime)
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'leave_requests') then
    execute 'alter publication supabase_realtime add table public.leave_requests';
  end if;
end $$;


-- ===== calendar_all.sql =====
-- ============================================================
-- Kalendorius visiems: renginiai, vykstantys tą dieną, matomi visiems
-- prisijungusiems nariams (net jei jie nemato „Renginių“ skilties) –
-- tik pavadinimas, datos ir vieta, be kitos renginio informacijos.
-- my_roles – kur tu pats įrašytas (komandos lentelėse ar vadovu),
-- atpažįstama pagal vardą ir pavardę arba slapyvardį, kaip programėlėje.
-- Kas atostogauja, grąžina leave_busy() (leave.sql).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.norm_name(t text) returns text
  language sql immutable as $$
  select trim(regexp_replace(regexp_replace(translate(lower(coalesce(t, '')), 'ąčęėįšųūž', 'aceeisuuz'), '[^a-z0-9 ]', ' ', 'g'), '\s+', ' ', 'g'))
$$;

create or replace function public.calendar_events(d_from date, d_to date)
  returns table (id text, kind text, name text, date_from date, date_to date, venue text, my_roles text[])
  language sql stable security definer set search_path = public as $$
  with me as (
    select public.norm_name(concat_ws(' ', p.first_name, p.last_name)) as n1,
           nullif(public.norm_name(p.nickname), '') as n2
      from public.profiles p where p.id = auth.uid()
  ), ev as (
    select e.id, e.data,
           (e.data->>'date')::date as d1,
           case when coalesce(e.data->>'dateEnd', '') ~ '^\d{4}-\d{2}-\d{2}$' and (e.data->>'dateEnd')::date >= (e.data->>'date')::date
                then (e.data->>'dateEnd')::date else (e.data->>'date')::date end as d2
      from public.events e
     where coalesce(e.data->>'date', '') ~ '^\d{4}-\d{2}-\d{2}$'
       and coalesce(e.data->>'deletedAt', '') = ''
       and coalesce(e.data->>'handoverId', '') = ''
  )
  select ev.id,
         case when ev.data->>'kind' = 'work' then 'work' else 'event' end,
         case when ev.data->>'kind' = 'work' then coalesce(nullif(ev.data->>'title', ''), 'Sandėlio darbai')
              else coalesce(nullif(ev.data->>'name', ''), 'Renginys') end,
         ev.d1, ev.d2,
         nullif(coalesce(nullif(ev.data->>'venue', ''), case when jsonb_typeof(ev.data->'location') = 'string' then ev.data->>'location' end), ''),
         array(
           select concat_ws(' · ', nullif(g->>'title', ''), nullif(en->>'pos', ''))
             from jsonb_array_elements(case when jsonb_typeof(ev.data->'crew') = 'array' then ev.data->'crew' else '[]'::jsonb end) g,
                  jsonb_array_elements(case when jsonb_typeof(g->'entries') = 'array' then g->'entries' else '[]'::jsonb end) en, me
            where public.norm_name(en->>'person') <> '' and public.norm_name(en->>'person') in (me.n1, me.n2)
           union all
           select 'Vadovas' from me
            where public.norm_name(ev.data->>'manager') <> '' and public.norm_name(ev.data->>'manager') in (me.n1, me.n2)
         )
    from ev
   where public.is_approved()
     and ev.d1 <= d_to and ev.d2 >= d_from
     and d_to - d_from <= 120
   order by ev.d1, 3
$$;
revoke all on function public.calendar_events(date, date) from public, anon;
grant execute on function public.calendar_events(date, date) to authenticated;


-- ===== contact_rates.sql =====
-- ============================================================
-- Žmonės (Bookingas / Archyvas): valandinis ir stafkė
--  * atskira lentelė, kad įkainių nematytų visi, kas mato „Žmones“
--    (kontaktų lentelę skaito visi su „Žmonių“ teise)
--  * mato ir keičia tik office, projektų vadovai (pm) ir admin
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.contact_rates (
  contact_id  text primary key references public.contacts(id) on delete cascade,
  hourly      numeric(10,2) check (hourly is null or (hourly >= 0 and hourly < 100000)),
  daily       numeric(10,2) check (daily is null or (daily >= 0 and daily < 1000000)),
  note        text,
  updated_at  timestamptz not null default now(),
  updated_by  uuid default auth.uid()
);

create or replace function public.rates_access() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role in ('admin','pm','office') from public.profiles where id = auth.uid()), false)
$$;
revoke all on function public.rates_access() from public, anon;
grant execute on function public.rates_access() to authenticated;

alter table public.contact_rates enable row level security;
drop policy if exists "rates view" on public.contact_rates;
create policy "rates view" on public.contact_rates for select to authenticated using (public.rates_access());
drop policy if exists "rates change" on public.contact_rates;
create policy "rates change" on public.contact_rates for all to authenticated
  using (public.rates_access()) with check (public.rates_access());
revoke all on public.contact_rates from anon;
grant select, insert, update, delete on public.contact_rates to authenticated;

create or replace function public.contact_rates_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  new.updated_at := now();
  if auth.uid() is not null then new.updated_by := auth.uid(); end if;
  return new;
end $$;
drop trigger if exists contact_rates_stamp on public.contact_rates;
create trigger contact_rates_stamp before insert or update on public.contact_rates
  for each row execute function public.contact_rates_stamp();


-- ===== vehicle_logs.sql =====
-- ============================================================
-- Transportas: automobilių tvarkymai ir pastebėtos problemos
--  * kind 'service' – tvarkymas (data, rida, kategorija, kas atlikta,
--    servisas, kaina, sąskaitos) – registruoja tas, kas redaguoja „Transportą“
--  * kind 'problem' – pastebėta problema (data, rida, aprašymas, kaip skubu,
--    nuotraukos) – gali pranešti visi, kas mato „Transportą“;
--    status 'open' → 'fixed' (fixed_by – tvarkymas, kuriuo sutvarkyta)
--  * failai (sąskaitos PDF, nuotraukos): saugykla 'fleet-files',
--    kelias <vehicle_id>/<įrašo id>/<failas>
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.vehicle_logs (
  id               uuid primary key default gen_random_uuid(),
  vehicle_id       text not null,
  vehicle_name     text,
  kind             text not null check (kind in ('service','problem')),
  log_date         date not null default current_date,
  mileage          integer check (mileage is null or (mileage >= 0 and mileage < 10000000)),
  category         text,
  title            text not null default '',
  description      text not null default '',
  place            text,
  cost             numeric(12,2) check (cost is null or (cost >= 0 and cost < 10000000)),
  severity         text check (severity is null or severity in ('low','soon','stop')),
  status           text not null default 'open' check (status in ('open','fixed','done')),
  fixed_by         uuid,
  fixed_at         date,
  files            jsonb not null default '[]'::jsonb,
  created_by       uuid not null default auth.uid(),
  created_by_name  text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);
create index if not exists vehicle_logs_vehicle on public.vehicle_logs (vehicle_id, log_date desc);
create index if not exists vehicle_logs_date on public.vehicle_logs (log_date);

alter table public.vehicle_logs enable row level security;
drop policy if exists "fleet logs view" on public.vehicle_logs;
create policy "fleet logs view" on public.vehicle_logs for select to authenticated
  using (public.can_view('fleet'));
drop policy if exists "fleet logs add" on public.vehicle_logs;
create policy "fleet logs add" on public.vehicle_logs for insert to authenticated
  with check (public.can_view('fleet') and created_by = auth.uid() and (kind = 'problem' or public.can_edit('fleet')));
drop policy if exists "fleet logs change" on public.vehicle_logs;
create policy "fleet logs change" on public.vehicle_logs for update to authenticated
  using (public.can_edit('fleet') or created_by = auth.uid())
  with check (public.can_edit('fleet') or (created_by = auth.uid() and kind = 'problem'));
drop policy if exists "fleet logs delete" on public.vehicle_logs;
create policy "fleet logs delete" on public.vehicle_logs for delete to authenticated
  using (public.can_edit('fleet') or created_by = auth.uid());
revoke all on public.vehicle_logs from anon;
grant select, insert, update, delete on public.vehicle_logs to authenticated;

-- kas įrašė ir kada – nustato serveris
create or replace function public.vehicle_logs_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  if tg_op = 'INSERT' then
    new.created_by := auth.uid();
    new.created_at := now();
    new.created_by_name := coalesce((select nullif(trim(concat_ws(' ', p.first_name, p.last_name)), '') from public.profiles p where p.id = auth.uid()), new.created_by_name);
  else
    new.created_by := old.created_by; new.created_at := old.created_at; new.created_by_name := old.created_by_name;
    new.kind := old.kind;
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists vehicle_logs_stamp on public.vehicle_logs;
create trigger vehicle_logs_stamp before insert or update on public.vehicle_logs
  for each row execute function public.vehicle_logs_stamp();

-- pokyčiai iš karto (Realtime)
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'vehicle_logs') then
    execute 'alter publication supabase_realtime add table public.vehicle_logs';
  end if;
end $$;

-- sąskaitos ir nuotraukos
insert into storage.buckets (id, name, public) values ('fleet-files', 'fleet-files', false) on conflict (id) do nothing;
drop policy if exists "fleet files view" on storage.objects;
create policy "fleet files view" on storage.objects for select to authenticated
  using (bucket_id = 'fleet-files' and public.can_view('fleet'));
drop policy if exists "fleet files add" on storage.objects;
create policy "fleet files add" on storage.objects for insert to authenticated
  with check (bucket_id = 'fleet-files' and public.can_view('fleet'));
drop policy if exists "fleet files delete" on storage.objects;
create policy "fleet files delete" on storage.objects for delete to authenticated
  using (bucket_id = 'fleet-files' and (public.can_edit('fleet') or owner = auth.uid()));

-- ============================================================
-- Windows programa (Event Solutions .exe): pranešimai kompiuteryje
--  * Web Push kompiuterio programoje neveikia, todėl push-notify kiekvieną
--    pranešimą dar įrašo į desktop_inbox tiems, kas naudoja programą
--    (desktop_clients – kas ir kada paskutinį kartą ją atidarė)
--  * programa klauso savo eilučių (Realtime) ir rodo Windows pranešimą
--  * senesni nei 3 d. įrašai ištrinami automatiškai
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.desktop_clients (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  last_seen  timestamptz not null default now()
);
alter table public.desktop_clients enable row level security;
drop policy if exists "desktop clients own" on public.desktop_clients;
create policy "desktop clients own" on public.desktop_clients for select to authenticated using (user_id = auth.uid());
revoke all on public.desktop_clients from anon, authenticated;
grant select on public.desktop_clients to authenticated;

create table if not exists public.desktop_inbox (
  id          bigint generated always as identity primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  title       text not null default '',
  body        text not null default '',
  tag         text,
  url         text,
  kind        text,
  created_at  timestamptz not null default now()
);
create index if not exists desktop_inbox_user on public.desktop_inbox (user_id, id);
create index if not exists desktop_inbox_age on public.desktop_inbox (created_at);
alter table public.desktop_inbox enable row level security;
drop policy if exists "desktop inbox own" on public.desktop_inbox;
create policy "desktop inbox own" on public.desktop_inbox for select to authenticated using (user_id = auth.uid());
revoke all on public.desktop_inbox from anon, authenticated;
grant select on public.desktop_inbox to authenticated;

-- programa praneša, kad šis narys ją naudoja (kviečiama ją atidarius)
create or replace function public.desktop_register() returns void
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or not public.is_approved() then return; end if;
  insert into public.desktop_clients (user_id, last_seen) values (auth.uid(), now())
    on conflict (user_id) do update set last_seen = now();
end $$;
revoke all on function public.desktop_register() from public, anon;
grant execute on function public.desktop_register() to authenticated;

-- nauji pranešimai iš karto (Realtime)
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'desktop_inbox') then
    execute 'alter publication supabase_realtime add table public.desktop_inbox';
  end if;
end $$;
-- ============================================================
-- Chato skambučiai: vaizdo arba garso (Daily.co)
--  * media 'video' – su kamera, 'audio' – tik garsas (kameras galima įsijungti)
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.calls add column if not exists media text not null default 'video';
alter table public.calls drop constraint if exists calls_media_check;
alter table public.calls add constraint calls_media_check check (media in ('video','audio'));

-- ============================================================
-- Windows programos atnaujinimai: saugykla „desktop“ (vieša, tik skaityti)
--  * GitHub (.github/workflows/desktop.yml) pats sukuria EventSolutions-Setup.exe,
--    padalina į dalis po 24 MB ir įkelia čia kartu su EventSolutions-Setup.json
--  * programa ir svetainės mygtukas „Atsisiųsti Windows (.exe)“ ima iš čia
--    (svetainės _redirects nukreipia senus adresus)
--  * įkelti gali tik serveris (service_role), visi kiti – tik atsisiųsti
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

insert into storage.buckets (id, name, public, file_size_limit)
values ('desktop', 'desktop', true, 52428800)
on conflict (id) do update set public = true, file_size_limit = 52428800;

-- ============================================================
-- Admin → „Limitai ir naudojimas“: kiek užima duomenų bazė ir failų saugykla
--  * admin_usage() – tik administratoriams (role = 'admin')
--  * duomenų bazės dydis, didžiausios lentelės, failai pagal saugyklas
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.admin_usage() returns jsonb
  language plpgsql stable security definer set search_path = public, storage as $$
declare r jsonb;
begin
  if not coalesce((select role = 'admin' from public.profiles where id = auth.uid()), false) then
    raise exception 'Tik administratoriams';
  end if;
  select jsonb_build_object(
    'db_bytes', pg_database_size(current_database()),
    'tables', coalesce((select jsonb_agg(t) from (
        select c.relname as name, pg_total_relation_size(c.oid) as bytes, c.reltuples::bigint as rows
          from pg_class c join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'public' and c.relkind = 'r'
         order by pg_total_relation_size(c.oid) desc limit 8) t), '[]'::jsonb),
    'buckets', coalesce((select jsonb_agg(b) from (
        select o.bucket_id as name, count(*) as files, coalesce(sum((o.metadata->>'size')::bigint), 0) as bytes
          from storage.objects o group by o.bucket_id order by 3 desc) b), '[]'::jsonb),
    'members', (select count(*) from public.profiles where role <> 'pending'),
    'at', now()
  ) into r;
  return r;
end $$;
revoke all on function public.admin_usage() from public, anon;
grant execute on function public.admin_usage() to authenticated;


-- ============================================================
-- Kalendorius: susitikimai su žmonėmis iš išorės (svečiais)
--  * kiekvienas pakviestas el. paštu gauna asmeninę nuorodą (?svecias=<raktas>):
--    „Dalyvausiu / Nedalyvausiu“, susitikimo informacija, pridėti į kalendorių
--  * „Online susitikimas“: dar ir pokalbis (žinutės, failai, bendri užrašai) ir
--    vaizdo skambutis; nariai jį mato chate kaip grupę „🤝 <tema>“
--  * visiems išėjus iš skambučio jis baigiamas, visiems išsiunčiama santrauka
--    (užrašai, failai, žinutės)
--  * svečiai jungiasi tik per funkciją „guest“ (su raktu), tiesiai į duomenų bazę – ne
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.meetings add column if not exists online boolean not null default false;
alter table public.meetings add column if not exists conversation_id uuid references public.conversations(id) on delete set null;
alter table public.meetings add column if not exists notes text not null default '';
alter table public.meetings add column if not exists summary_sent_at timestamptz;

create table if not exists public.meeting_guests (
  id           uuid primary key default gen_random_uuid(),
  meeting_id   uuid not null references public.meetings(id) on delete cascade,
  email        text not null,
  name         text,
  token        text not null unique default (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  status       text not null default 'pending' check (status in ('pending','yes','no')),
  responded_at timestamptz,
  last_seen_at timestamptz,
  created_at   timestamptz not null default now(),
  unique (meeting_id, email)
);
create index if not exists meeting_guests_meeting on public.meeting_guests (meeting_id);
alter table public.meeting_guests enable row level security;
-- the organizer and the invited members see who answered (and the organizer can copy the links)
drop policy if exists "meeting guests view" on public.meeting_guests;
create policy "meeting guests view" on public.meeting_guests for select to authenticated using (
  exists (select 1 from public.meetings m where m.id = meeting_id and (m.created_by = auth.uid() or auth.uid() = any (m.attendees))));
revoke all on public.meeting_guests from anon, authenticated;
grant select on public.meeting_guests to authenticated;

-- the organizer and the invited members may write the shared notes
drop policy if exists "meeting notes by attendees" on public.meetings;
create or replace function public.meeting_set_notes(p_id uuid, p_notes text) returns void
  language plpgsql security definer set search_path = public as $$
begin
  update public.meetings set notes = left(coalesce(p_notes, ''), 20000), updated_at = now()
   where id = p_id and (created_by = auth.uid() or auth.uid() = any (attendees));
end $$;
revoke all on function public.meeting_set_notes(uuid, text) from public, anon;
grant execute on function public.meeting_set_notes(uuid, text) to authenticated;

-- a guest's message: kept with the organizer as sender (the table needs a member),
-- the guest's name shown instead
alter table public.messages add column if not exists guest_id uuid references public.meeting_guests(id) on delete set null;
alter table public.messages add column if not exists guest_name text;

-- live answers for the organizer's screen
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'meeting_guests') then
    execute 'alter publication supabase_realtime add table public.meeting_guests';
  end if;
end $$;

-- ---------- pokalbių sąrašas: svečių žinutės neperskaitytos ir organizatoriui ----------
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
           where x.conversation_id = c.id and x.deleted_at is null and (x.sender_id <> auth.uid() or x.guest_id is not null)
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


-- ============================================================
-- Balsavimai (Admin → Balsavimai): klausimas su atsakymų variantais,
-- balsuojama telefonu per QR nuorodą, rezultatai – atskira nuoroda
-- (pvz. LED ekranui / OBS, nustatyto dydžio pikseliais).
--  * tvarko tik administratoriai (lentelės matomos tik jiems)
--  * balsuotojai ir rezultatų ekranas – be prisijungimo, tik per slaptą
--    nuorodą (funkcijos poll_public / poll_vote / poll_results)
--  * pasibaigus balsavimui klausimas paslepiamas; paleidus iš naujo –
--    naujas QR kodas (senasis nebegalioja), skaičiuojama nuo nulio
--  * fonas ir šriftas – vieša saugykla „poll-assets“
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.polls (
  id            uuid primary key default gen_random_uuid(),
  question      text not null default '' check (char_length(question) <= 500),
  options       jsonb not null default '[]'::jsonb,          -- [{ id, text }]
  duration_sec  int not null default 60 check (duration_sec between 5 and 86400),
  starts_at     timestamptz,                                 -- balsavimo pradžia (gali būti ateityje)
  ends_at       timestamptz,                                 -- pabaiga
  round         int not null default 0,                      -- kelintas paleidimas (balsai skaičiuojami tik šio)
  vote_token    text not null unique default (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  results_token text not null unique default (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  brand         jsonb not null default '{}'::jsonb,          -- { bg, font, fontName, color, accent }
  results_w     int not null default 1920 check (results_w between 100 and 8000),
  results_h     int not null default 1080 check (results_h between 100 and 8000),
  created_by    uuid default auth.uid() references auth.users(id) on delete set null,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create table if not exists public.poll_votes (
  id         bigint generated always as identity primary key,
  poll_id    uuid not null references public.polls(id) on delete cascade,
  round      int not null,
  option_id  text not null,
  voter      text not null,                                  -- atsitiktinis telefono raktas
  created_at timestamptz not null default now(),
  unique (poll_id, round, voter)
);
create index if not exists poll_votes_poll on public.poll_votes (poll_id, round);

alter table public.polls enable row level security;
alter table public.poll_votes enable row level security;
revoke all on public.polls, public.poll_votes from anon, authenticated;
grant select, insert, update, delete on public.polls to authenticated;
grant select, delete on public.poll_votes to authenticated;
drop policy if exists "polls admin" on public.polls;
create policy "polls admin" on public.polls for all to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "poll votes admin" on public.poll_votes;
create policy "poll votes admin" on public.poll_votes for select to authenticated using (public.is_admin());
drop policy if exists "poll votes admin delete" on public.poll_votes;
create policy "poll votes admin delete" on public.poll_votes for delete to authenticated using (public.is_admin());

-- ---------- administratoriui: pradėti (po p_delay sekundžių) ir sustabdyti ----------
-- pirmą kartą paleidžiant QR kodas lieka tas pats (jį galima parodyti iš anksto);
-- kiekvieną kitą kartą – naujas, o balsai skaičiuojami nuo nulio
create or replace function public.poll_start(p_id uuid, p_delay int default 0) returns public.polls
  language plpgsql security definer set search_path = public as $$
declare p public.polls; t timestamptz := now() + make_interval(secs => greatest(0, least(coalesce(p_delay, 0), 86400)));
begin
  if not public.is_admin() then raise exception 'Tik administratoriui'; end if;
  update public.polls set
      vote_token = case when round = 0 and starts_at is null then vote_token
                        else replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '') end,
      round = round + 1, starts_at = t, ends_at = t + make_interval(secs => duration_sec), updated_at = now()
    where id = p_id returning * into p;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return p;
end $$;

create or replace function public.poll_stop(p_id uuid) returns public.polls
  language plpgsql security definer set search_path = public as $$
declare p public.polls;
begin
  if not public.is_admin() then raise exception 'Tik administratoriui'; end if;
  update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
    where id = p_id and ends_at > now() returning * into p;
  if p.id is null then select * into p from public.polls where id = p_id; end if;
  return p;
end $$;
revoke all on function public.poll_start(uuid, int), public.poll_stop(uuid) from public, anon;
grant execute on function public.poll_start(uuid, int), public.poll_stop(uuid) to authenticated;

-- ---------- viešai (be prisijungimo) ----------
create or replace function public.poll_state(p public.polls) returns text language sql stable as $$
  select case when p.starts_at is null then 'draft'
              when now() < p.starts_at then 'waiting'
              when now() < p.ends_at then 'live'
              else 'ended' end
$$;

-- balsuotojo puslapis (QR): pasibaigus – klausimas nerodomas
create or replace function public.poll_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; st text;
begin
  select * into p from public.polls where vote_token = p_token;
  if p.id is null then return jsonb_build_object('state', 'invalid', 'now', now()); end if;
  st := public.poll_state(p);
  return jsonb_build_object('state', st, 'now', now(), 'round', p.round, 'starts_at', p.starts_at, 'ends_at', p.ends_at,
    'brand', p.brand,
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;

create or replace function public.poll_vote(p_token text, p_option text, p_voter text) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls;
begin
  select * into p from public.polls where vote_token = p_token;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if coalesce(length(p_voter), 0) not between 8 and 100 then return 'bad'; end if;
  if not exists (select 1 from jsonb_array_elements(p.options) o where o->>'id' = p_option) then return 'bad'; end if;
  insert into public.poll_votes (poll_id, round, option_id, voter) values (p.id, p.round, p_option, p_voter)
    on conflict (poll_id, round, voter) do nothing;
  if not found then return 'already'; end if;
  return 'ok';
end $$;

-- rezultatų ekranas (ir redaktoriaus peržiūra): šio paleidimo balsai
create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls;
begin
  select * into p from public.polls where results_token = p_token;
  if p.id is null then return jsonb_build_object('state', 'invalid'); end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'round', p.round, 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', p.brand, 'w', p.results_w, 'h', p.results_h,
    'total', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
revoke all on function public.poll_state(public.polls), public.poll_public(text), public.poll_vote(text, text, text), public.poll_results(text) from public;
grant execute on function public.poll_public(text), public.poll_vote(text, text, text), public.poll_results(text) to anon, authenticated;
grant execute on function public.poll_state(public.polls) to authenticated;

-- ---------- fonas ir šriftas: vieša saugykla, įkelti gali tik administratoriai ----------
insert into storage.buckets (id, name, public) values ('poll-assets', 'poll-assets', true)
  on conflict (id) do update set public = true;
drop policy if exists "poll assets admin insert" on storage.objects;
create policy "poll assets admin insert" on storage.objects for insert to authenticated with check (bucket_id = 'poll-assets' and public.is_admin());
drop policy if exists "poll assets admin update" on storage.objects;
create policy "poll assets admin update" on storage.objects for update to authenticated using (bucket_id = 'poll-assets' and public.is_admin());
drop policy if exists "poll assets admin delete" on storage.objects;
create policy "poll assets admin delete" on storage.objects for delete to authenticated using (bucket_id = 'poll-assets' and public.is_admin());


-- ============================================================
-- Balsavimai, 2 dalis (paleisti po polls.sql):
--  * redaktoriaus nuoroda (?balsavimai=<raktas>): kas ją turi, tas be
--    prisijungimo kuria, redaguoja, paleidžia ir stabdo balsavimus.
--    Nuorodą sukuria / pakeičia / išjungia administratorius.
--  * visi redaktoriaus veiksmai – per vieną funkciją poll_admin
--    (administratoriui arba su galiojančiu raktu)
--  * fonas, logotipas ir šriftas saugomi duomenų bazėje (poll_assets),
--    todėl įkelti gali ir redaktorius be prisijungimo
--  * klausimų eiliškumas (sort)
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.polls add column if not exists sort int not null default 0;

create table if not exists public.poll_settings (
  id           int primary key default 1 check (id = 1),
  editor_token text,
  editor_on    boolean not null default false,
  updated_at   timestamptz not null default now()
);
alter table public.poll_settings enable row level security;
revoke all on public.poll_settings from anon, authenticated;

create table if not exists public.poll_assets (
  id         uuid primary key default gen_random_uuid(),
  mime       text not null,
  data       text not null,                    -- base64
  bytes      int not null,
  created_at timestamptz not null default now()
);
alter table public.poll_assets enable row level security;
revoke all on public.poll_assets from anon, authenticated;

-- administratorius arba galiojantis redaktoriaus raktas
create or replace function public.poll_key_ok(p_key text) returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.is_admin(), false)
      or (coalesce(length(p_key), 0) = 64
          and exists (select 1 from public.poll_settings s where s.id = 1 and s.editor_on and s.editor_token = p_key))
$$;
revoke all on function public.poll_key_ok(text) from public;

-- administratoriui: redaktoriaus nuoroda ('get' | 'new' | 'on' | 'off')
create or replace function public.poll_editor_link(p_action text) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare s public.poll_settings; t text := replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');
begin
  if not coalesce(public.is_admin(), false) then raise exception 'Tik administratoriui'; end if;
  if p_action = 'new' then
    insert into public.poll_settings (id, editor_token, editor_on) values (1, t, true)
      on conflict (id) do update set editor_token = t, editor_on = true, updated_at = now();
  elsif p_action = 'on' then
    insert into public.poll_settings (id, editor_token, editor_on) values (1, t, true)
      on conflict (id) do update set editor_on = true, editor_token = coalesce(poll_settings.editor_token, t), updated_at = now();
  elsif p_action = 'off' then
    update public.poll_settings set editor_on = false, updated_at = now() where id = 1;
  end if;
  select * into s from public.poll_settings where id = 1;
  return jsonb_build_object('token', case when s.editor_on then s.editor_token end, 'on', coalesce(s.editor_on, false));
end $$;
revoke all on function public.poll_editor_link(text) from public, anon;
grant execute on function public.poll_editor_link(text) to authenticated;

-- paleisti / sustabdyti (bendra administratoriui ir redaktoriui)
create or replace function public.poll_do_start(p_id uuid, p_delay int) returns public.polls
  language plpgsql security definer set search_path = public as $$
declare p public.polls; t timestamptz := now() + make_interval(secs => greatest(0, least(coalesce(p_delay, 0), 86400)));
begin
  update public.polls set
      vote_token = case when round = 0 and starts_at is null then vote_token
                        else replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '') end,
      round = round + 1, starts_at = t, ends_at = t + make_interval(secs => duration_sec), updated_at = now()
    where id = p_id returning * into p;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return p;
end $$;
create or replace function public.poll_do_stop(p_id uuid) returns public.polls
  language plpgsql security definer set search_path = public as $$
declare p public.polls;
begin
  update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
    where id = p_id and ends_at > now() returning * into p;
  if p.id is null then select * into p from public.polls where id = p_id; end if;
  return p;
end $$;
revoke all on function public.poll_do_start(uuid, int), public.poll_do_stop(uuid) from public, anon, authenticated;

create or replace function public.poll_start(p_id uuid, p_delay int default 0) returns public.polls
  language plpgsql security definer set search_path = public as $$
begin
  if not coalesce(public.is_admin(), false) then raise exception 'Tik administratoriui'; end if;
  return public.poll_do_start(p_id, p_delay);
end $$;
create or replace function public.poll_stop(p_id uuid) returns public.polls
  language plpgsql security definer set search_path = public as $$
begin
  if not coalesce(public.is_admin(), false) then raise exception 'Tik administratoriui'; end if;
  return public.poll_do_stop(p_id);
end $$;

-- visi redaktoriaus veiksmai
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; v_id uuid; v_new uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  if p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x), '[]'::jsonb);
  elsif p_action = 'create' then
    insert into public.polls (question, options, duration_sec, brand, results_w, results_h, sort, created_by)
      values (left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb), coalesce((a->>'duration_sec')::int, 60),
              coalesce(a->'brand', '{}'::jsonb), coalesce((a->>'results_w')::int, 1920), coalesce((a->>'results_h')::int, 1080),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls)), auth.uid())
      returning * into p;
    return to_jsonb(p);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    insert into public.poll_assets (mime, data, bytes) values (a->>'mime', a->>'data', length(a->>'data') * 3 / 4) returning id into v_new;
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        question = left(coalesce(a->>'question', question), 500), options = coalesce(a->'options', options),
        duration_sec = coalesce((a->>'duration_sec')::int, duration_sec), brand = coalesce(a->'brand', brand),
        results_w = coalesce((a->>'results_w')::int, results_w), results_h = coalesce((a->>'results_h')::int, results_h),
        sort = coalesce((a->>'sort')::int, sort), updated_at = now()
      where id = v_id returning * into p;
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'stop' then
    p := public.poll_do_stop(v_id);
  else
    raise exception 'Nežinomas veiksmas';
  end if;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return to_jsonb(p);
end $$;
revoke all on function public.poll_admin(text, text, jsonb) from public;
grant execute on function public.poll_admin(text, text, jsonb) to anon, authenticated;

-- fonas / logotipas / šriftas balsavimo ir rezultatų puslapiams (viešai)
create or replace function public.poll_asset(p_id uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('mime', mime, 'data', data) from public.poll_assets where id = p_id
$$;
revoke all on function public.poll_asset(uuid) from public;
grant execute on function public.poll_asset(uuid) to anon, authenticated;


-- ============================================================
-- Balsavimai, 3 dalis (paleisti po polls.sql ir polls2.sql):
--  * apipavidalinimas ir rezultatų ekrano dydis – bendri VISIEMS klausimams
--    (seniems ir naujiems), saugomi poll_settings. Pirmą kartą paimamas
--    paskutinio redaguoto klausimo apipavidalinimas.
--  * VIENAS nuolatinis QR kodas (?balsuoti=<raktas>) ir viena rezultatų
--    nuoroda visiems klausimams – niekada nesikeičia. Rodomas tuo metu
--    vykstantis klausimas; jei nevyksta nė vienas – tik fonas ir logotipas.
--  * paleidus klausimą, kitas tuo metu vykstantis sustabdomas
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.poll_settings add column if not exists brand jsonb;
alter table public.poll_settings add column if not exists results_w int;
alter table public.poll_settings add column if not exists results_h int;

insert into public.poll_settings (id) values (1) on conflict (id) do nothing;
update public.poll_settings s set
    brand = coalesce(s.brand, (select p.brand from public.polls p where p.brand <> '{}'::jsonb order by p.updated_at desc limit 1), '{}'::jsonb),
    results_w = coalesce(s.results_w, (select p.results_w from public.polls p order by p.updated_at desc limit 1), 1920),
    results_h = coalesce(s.results_h, (select p.results_h from public.polls p order by p.updated_at desc limit 1), 1080)
  where s.id = 1;

-- the shared look (for the pages)
create or replace function public.poll_look() returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('brand', coalesce(brand, '{}'::jsonb), 'w', coalesce(results_w, 1920), 'h', coalesce(results_h, 1080))
    from public.poll_settings where id = 1
$$;
revoke all on function public.poll_look() from public, anon, authenticated;

create or replace function public.poll_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; st text; lk jsonb := coalesce(public.poll_look(), '{}'::jsonb);
begin
  select * into p from public.polls where vote_token = p_token;
  if p.id is null then return jsonb_build_object('state', 'invalid', 'now', now(), 'brand', lk->'brand'); end if;
  st := public.poll_state(p);
  return jsonb_build_object('state', st, 'now', now(), 'round', p.round, 'starts_at', p.starts_at, 'ends_at', p.ends_at,
    'brand', coalesce(lk->'brand', p.brand),
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; lk jsonb := coalesce(public.poll_look(), '{}'::jsonb);
begin
  select * into p from public.polls where results_token = p_token;
  if p.id is null then return jsonb_build_object('state', 'invalid'); end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'round', p.round, 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(lk->'brand', p.brand),
    'w', coalesce((lk->>'w')::int, p.results_w), 'h', coalesce((lk->>'h')::int, p.results_h),
    'total', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
grant execute on function public.poll_public(text), public.poll_results(text) to anon, authenticated;

-- the editor: + 'look' (read) and 'set_look' (save) for the shared look
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; v_id uuid; v_new uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  if p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x), '[]'::jsonb);
  elsif p_action = 'look' then
    return public.poll_look();
  elsif p_action = 'set_look' then
    insert into public.poll_settings (id) values (1) on conflict (id) do nothing;
    update public.poll_settings set
        brand = coalesce(a->'brand', brand),
        results_w = greatest(100, least(8000, coalesce((a->>'results_w')::int, results_w, 1920))),
        results_h = greatest(100, least(8000, coalesce((a->>'results_h')::int, results_h, 1080))),
        updated_at = now()
      where id = 1;
    return public.poll_look();
  elsif p_action = 'create' then
    insert into public.polls (question, options, duration_sec, sort, created_by)
      values (left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb), coalesce((a->>'duration_sec')::int, 60),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls)), auth.uid())
      returning * into p;
    return to_jsonb(p);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    insert into public.poll_assets (mime, data, bytes) values (a->>'mime', a->>'data', length(a->>'data') * 3 / 4) returning id into v_new;
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        question = left(coalesce(a->>'question', question), 500), options = coalesce(a->'options', options),
        duration_sec = coalesce((a->>'duration_sec')::int, duration_sec),
        sort = coalesce((a->>'sort')::int, sort), updated_at = now()
      where id = v_id returning * into p;
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'stop' then
    p := public.poll_do_stop(v_id);
  else
    raise exception 'Nežinomas veiksmas';
  end if;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return to_jsonb(p);
end $$;
revoke all on function public.poll_admin(text, text, jsonb) from public;
grant execute on function public.poll_admin(text, text, jsonb) to anon, authenticated;


-- ---------- vienas nuolatinis QR kodas ir rezultatų nuoroda ----------
alter table public.poll_settings add column if not exists vote_token text;
alter table public.poll_settings add column if not exists results_token text;
update public.poll_settings set
    vote_token = coalesce(vote_token, replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
    results_token = coalesce(results_token, replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''))
  where id = 1;

create or replace function public.poll_look() returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('brand', coalesce(brand, '{}'::jsonb), 'w', coalesce(results_w, 1920), 'h', coalesce(results_h, 1080),
                            'vote_token', vote_token, 'results_token', results_token)
    from public.poll_settings where id = 1
$$;
revoke all on function public.poll_look() from public, anon, authenticated;

-- which question the permanent links show: the running one, else the next to start
create or replace function public.poll_current() returns public.polls
  language sql stable security definer set search_path = public as $$
  select * from (
    (select * from public.polls where starts_at <= now() and ends_at > now() order by starts_at desc limit 1)
    union all
    (select * from public.polls where starts_at > now() order by starts_at asc limit 1)
  ) x limit 1
$$;
revoke all on function public.poll_current() from public, anon, authenticated;

-- one question at a time: starting one stops the others
create or replace function public.poll_do_start(p_id uuid, p_delay int) returns public.polls
  language plpgsql security definer set search_path = public as $$
declare p public.polls; t timestamptz := now() + make_interval(secs => greatest(0, least(coalesce(p_delay, 0), 86400)));
begin
  update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
    where id <> p_id and ends_at > now();
  update public.polls set round = round + 1, starts_at = t, ends_at = t + make_interval(secs => duration_sec), updated_at = now()
    where id = p_id returning * into p;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return p;
end $$;
revoke all on function public.poll_do_start(uuid, int) from public, anon, authenticated;

create or replace function public.poll_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; st text; lk jsonb := coalesce(public.poll_look(), '{}'::jsonb); perm boolean := p_token is not null and p_token = lk->>'vote_token';
begin
  if perm then p := public.poll_current();
  else select * into p from public.polls where vote_token = p_token; end if;
  if p.id is null then return jsonb_build_object('state', case when perm then 'idle' else 'invalid' end, 'now', now(), 'brand', lk->'brand'); end if;
  st := public.poll_state(p);
  if perm and st not in ('waiting', 'live') then st := 'idle'; end if;
  return jsonb_build_object('state', st, 'now', now(), 'poll', p.id, 'round', p.round, 'starts_at', p.starts_at, 'ends_at', p.ends_at,
    'brand', coalesce(lk->'brand', p.brand),
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;

-- a vote through the permanent QR names the question it was cast for
create or replace function public.poll_vote(p_token text, p_option text, p_voter text, p_poll uuid) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls; lk jsonb := coalesce(public.poll_look(), '{}'::jsonb);
begin
  if p_token is not null and p_token = lk->>'vote_token' then select * into p from public.polls where id = p_poll;
  else select * into p from public.polls where vote_token = p_token; end if;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if coalesce(length(p_voter), 0) not between 8 and 100 then return 'bad'; end if;
  if not exists (select 1 from jsonb_array_elements(p.options) o where o->>'id' = p_option) then return 'bad'; end if;
  insert into public.poll_votes (poll_id, round, option_id, voter) values (p.id, p.round, p_option, p_voter)
    on conflict (poll_id, round, voter) do nothing;
  if not found then return 'already'; end if;
  return 'ok';
end $$;
revoke all on function public.poll_vote(text, text, text, uuid) from public;
grant execute on function public.poll_vote(text, text, text, uuid) to anon, authenticated;

-- the permanent results link: the running question, else the last one that ended
create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; lk jsonb := coalesce(public.poll_look(), '{}'::jsonb); perm boolean := p_token is not null and p_token = lk->>'results_token';
begin
  if perm then
    p := public.poll_current();
    if p.id is null then select * into p from public.polls where ends_at <= now() order by ends_at desc limit 1; end if;
  else select * into p from public.polls where results_token = p_token; end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', lk->'brand', 'w', (lk->>'w')::int, 'h', (lk->>'h')::int)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(lk->'brand', p.brand),
    'w', coalesce((lk->>'w')::int, p.results_w), 'h', coalesce((lk->>'h')::int, p.results_h),
    'total', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
grant execute on function public.poll_public(text), public.poll_results(text) to anon, authenticated;


-- ============================================================
-- Balsavimai, 4 dalis (paleisti po polls3.sql): klausimo TEMA –
-- rodoma balsavimo puslapyje ir rezultatų ekrane virš klausimo.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

alter table public.polls add column if not exists topic text not null default '';

create or replace function public.poll_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; st text; lk jsonb := coalesce(public.poll_look(), '{}'::jsonb); perm boolean := p_token is not null and p_token = lk->>'vote_token';
begin
  if perm then p := public.poll_current();
  else select * into p from public.polls where vote_token = p_token; end if;
  if p.id is null then return jsonb_build_object('state', case when perm then 'idle' else 'invalid' end, 'now', now(), 'brand', lk->'brand'); end if;
  st := public.poll_state(p);
  if perm and st not in ('waiting', 'live') then st := 'idle'; end if;
  return jsonb_build_object('state', st, 'now', now(), 'poll', p.id, 'round', p.round, 'starts_at', p.starts_at, 'ends_at', p.ends_at,
    'brand', coalesce(lk->'brand', p.brand),
    'topic', case when st in ('waiting', 'live') then nullif(p.topic, '') end,
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; lk jsonb := coalesce(public.poll_look(), '{}'::jsonb); perm boolean := p_token is not null and p_token = lk->>'results_token';
begin
  if perm then
    p := public.poll_current();
    if p.id is null then select * into p from public.polls where ends_at <= now() order by ends_at desc limit 1; end if;
  else select * into p from public.polls where results_token = p_token; end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', lk->'brand', 'w', (lk->>'w')::int, 'h', (lk->>'h')::int)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(lk->'brand', p.brand),
    'w', coalesce((lk->>'w')::int, p.results_w), 'h', coalesce((lk->>'h')::int, p.results_h),
    'total', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
grant execute on function public.poll_public(text), public.poll_results(text) to anon, authenticated;

create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; v_id uuid; v_new uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  if p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x), '[]'::jsonb);
  elsif p_action = 'look' then
    return public.poll_look();
  elsif p_action = 'set_look' then
    insert into public.poll_settings (id) values (1) on conflict (id) do nothing;
    update public.poll_settings set
        brand = coalesce(a->'brand', brand),
        results_w = greatest(100, least(8000, coalesce((a->>'results_w')::int, results_w, 1920))),
        results_h = greatest(100, least(8000, coalesce((a->>'results_h')::int, results_h, 1080))),
        updated_at = now()
      where id = 1;
    return public.poll_look();
  elsif p_action = 'create' then
    insert into public.polls (topic, question, options, duration_sec, sort, created_by)
      values (left(coalesce(a->>'topic', ''), 200), left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb), coalesce((a->>'duration_sec')::int, 60),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls)), auth.uid())
      returning * into p;
    return to_jsonb(p);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    insert into public.poll_assets (mime, data, bytes) values (a->>'mime', a->>'data', length(a->>'data') * 3 / 4) returning id into v_new;
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        topic = left(coalesce(a->>'topic', topic), 200), question = left(coalesce(a->>'question', question), 500), options = coalesce(a->'options', options),
        duration_sec = coalesce((a->>'duration_sec')::int, duration_sec),
        sort = coalesce((a->>'sort')::int, sort), updated_at = now()
      where id = v_id returning * into p;
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'stop' then
    p := public.poll_do_stop(v_id);
  else
    raise exception 'Nežinomas veiksmas';
  end if;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return to_jsonb(p);
end $$;
revoke all on function public.poll_admin(text, text, jsonb) from public;
grant execute on function public.poll_admin(text, text, jsonb) to anon, authenticated;


-- ============================================================
-- Balsavimai, 5 dalis (paleisti po polls.sql … polls4.sql):
--  * keli BALSAVIMAI su pavadinimais (poll_sets). Kiekvienas turi savo
--    klausimus, apipavidalinimą, nuolatinį QR kodą ir rezultatų nuorodą.
--    Esami klausimai ir QR kodas perkeliami į pirmą balsavimą
--    „Balsavimas“ (atsisiųstas QR kodas toliau veikia).
--  * klausimui – vienas arba keli pasirinkimai (polls.multi)
--  * rezultatų ekranas: tik nugalėtojas (arba visi atsakymai – show_all)
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.poll_sets (
  id            uuid primary key default gen_random_uuid(),
  name          text not null default 'Balsavimas' check (char_length(name) <= 200),
  vote_token    text not null unique default (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  results_token text not null unique default (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  brand         jsonb not null default '{}'::jsonb,
  results_w     int not null default 1920 check (results_w between 100 and 8000),
  results_h     int not null default 1080 check (results_h between 100 and 8000),
  show_all      boolean not null default false,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
alter table public.poll_sets enable row level security;
revoke all on public.poll_sets from anon, authenticated;

alter table public.polls add column if not exists set_id uuid references public.poll_sets(id) on delete cascade;
alter table public.polls add column if not exists multi boolean not null default false;
create index if not exists polls_set on public.polls (set_id);

-- the questions and the permanent QR so far become the first voting
do $$
declare s record; v uuid;
begin
  if not exists (select 1 from public.poll_sets) then
    select * into s from public.poll_settings where id = 1;
    insert into public.poll_sets (name, vote_token, results_token, brand, results_w, results_h)
      values ('Balsavimas',
              coalesce(s.vote_token, replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
              coalesce(s.results_token, replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
              coalesce(s.brand, '{}'::jsonb), coalesce(s.results_w, 1920), coalesce(s.results_h, 1080))
      returning id into v;
    update public.polls set set_id = v where set_id is null;
  end if;
  update public.polls set set_id = (select id from public.poll_sets order by created_at limit 1) where set_id is null;
end $$;

-- several choices: one row per chosen answer (one submission per phone)
alter table public.poll_votes drop constraint if exists poll_votes_poll_id_round_voter_key;
create unique index if not exists poll_votes_one_option on public.poll_votes (poll_id, round, voter, option_id);
create index if not exists poll_votes_voter on public.poll_votes (poll_id, round, voter);

-- which question a voting's links show: the running one, else the next to start
create or replace function public.poll_set_current(p_set uuid) returns public.polls
  language sql stable security definer set search_path = public as $$
  select * from (
    (select * from public.polls where set_id = p_set and starts_at <= now() and ends_at > now() order by starts_at desc limit 1)
    union all
    (select * from public.polls where set_id = p_set and starts_at > now() order by starts_at asc limit 1)
  ) x limit 1
$$;
revoke all on function public.poll_set_current(uuid) from public, anon, authenticated;

-- one question at a time in a voting: starting one stops the others there
create or replace function public.poll_do_start(p_id uuid, p_delay int) returns public.polls
  language plpgsql security definer set search_path = public as $$
declare p public.polls; t timestamptz := now() + make_interval(secs => greatest(0, least(coalesce(p_delay, 0), 86400)));
begin
  update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
    where id <> p_id and ends_at > now() and set_id is not distinct from (select set_id from public.polls where id = p_id);
  update public.polls set round = round + 1, starts_at = t, ends_at = t + make_interval(secs => duration_sec), updated_at = now()
    where id = p_id returning * into p;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return p;
end $$;
revoke all on function public.poll_do_start(uuid, int) from public, anon, authenticated;

create or replace function public.poll_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; st text; s public.poll_sets;
begin
  select * into s from public.poll_sets where vote_token = p_token;
  if s.id is not null then p := public.poll_set_current(s.id);
  else select * into p from public.polls where vote_token = p_token;
       if p.id is not null then select * into s from public.poll_sets where id = p.set_id; end if; end if;
  if p.id is null then return jsonb_build_object('state', case when s.id is not null then 'idle' else 'invalid' end, 'now', now(), 'brand', coalesce(s.brand, '{}'::jsonb)); end if;
  st := public.poll_state(p);
  if s.id is not null and p_token = s.vote_token and st not in ('waiting', 'live') then st := 'idle'; end if;
  return jsonb_build_object('state', st, 'now', now(), 'poll', p.id, 'round', p.round, 'starts_at', p.starts_at, 'ends_at', p.ends_at,
    'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'topic', case when st in ('waiting', 'live') then nullif(p.topic, '') end,
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;

-- a vote: one or several answers (several only when the question allows it)
create or replace function public.poll_vote_many(p_token text, p_options text[], p_voter text, p_poll uuid) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; opts text[];
begin
  select * into s from public.poll_sets where vote_token = p_token;
  if s.id is not null then select * into p from public.polls where id = p_poll and set_id = s.id;
  else select * into p from public.polls where vote_token = p_token; end if;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if coalesce(length(p_voter), 0) not between 8 and 100 then return 'bad'; end if;
  select array_agg(distinct x) into opts from unnest(coalesce(p_options, '{}'::text[])) x;
  if coalesce(array_length(opts, 1), 0) = 0 or (not p.multi and array_length(opts, 1) > 1) then return 'bad'; end if;
  if exists (select 1 from unnest(opts) x where not exists (select 1 from jsonb_array_elements(p.options) o where o->>'id' = x)) then return 'bad'; end if;
  perform pg_advisory_xact_lock(hashtext(p.id::text || ':' || p_voter));
  if exists (select 1 from public.poll_votes where poll_id = p.id and round = p.round and voter = p_voter) then return 'already'; end if;
  insert into public.poll_votes (poll_id, round, option_id, voter) select p.id, p.round, x, p_voter from unnest(opts) x;
  return 'ok';
end $$;
revoke all on function public.poll_vote_many(text, text[], text, uuid) from public;
grant execute on function public.poll_vote_many(text, text[], text, uuid) to anon, authenticated;

create or replace function public.poll_vote(p_token text, p_option text, p_voter text, p_poll uuid) returns text
  language sql security definer set search_path = public as $$
  select public.poll_vote_many(p_token, array[p_option], p_voter, p_poll)
$$;
create or replace function public.poll_vote(p_token text, p_option text, p_voter text) returns text
  language sql security definer set search_path = public as $$
  select public.poll_vote_many(p_token, array[p_option], p_voter, null)
$$;
revoke all on function public.poll_vote(text, text, text, uuid), public.poll_vote(text, text, text) from public;
grant execute on function public.poll_vote(text, text, text, uuid), public.poll_vote(text, text, text) to anon, authenticated;

-- results: 'total' = people who voted; each answer's votes (several answers → more than 100 % together)
create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  select * into s from public.poll_sets where results_token = p_token;
  if s.id is not null then
    perm := true;
    p := public.poll_set_current(s.id);
    if p.id is null then select * into p from public.polls where set_id = s.id and ends_at <= now() order by ends_at desc limit 1; end if;
  else
    select * into p from public.polls where results_token = p_token;
    if p.id is not null then select * into s from public.poll_sets where id = p.set_id; end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
grant execute on function public.poll_public(text), public.poll_results(text) to anon, authenticated;

-- the editor (admin, or anyone with the editor link)
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; s public.poll_sets; v_id uuid; v_new uuid; v_set uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  -- votings
  if p_action = 'sets' then
    return coalesce((select jsonb_agg(to_jsonb(x) || jsonb_build_object(
              'questions', (select count(*) from public.polls q where q.set_id = x.id),
              'live', (select count(*) from public.polls q where q.set_id = x.id and q.ends_at > now()))
            order by x.created_at desc) from public.poll_sets x), '[]'::jsonb);
  elsif p_action = 'set_create' then
    insert into public.poll_sets (name) values (left(coalesce(nullif(trim(a->>'name'), ''), 'Balsavimas'), 200)) returning * into s;
    return to_jsonb(s);
  elsif p_action = 'set_update' then
    update public.poll_sets set
        name = left(coalesce(nullif(trim(a->>'name'), ''), name), 200), brand = coalesce(a->'brand', brand),
        results_w = greatest(100, least(8000, coalesce((a->>'results_w')::int, results_w))),
        results_h = greatest(100, least(8000, coalesce((a->>'results_h')::int, results_h))),
        show_all = coalesce((a->>'show_all')::boolean, show_all), updated_at = now()
      where id = (a->>'id')::uuid returning * into s;
    if s.id is null then raise exception 'Balsavimas nerastas'; end if;
    return to_jsonb(s);
  elsif p_action = 'set_delete' then
    delete from public.poll_sets where id = (a->>'id')::uuid;
    return '{}'::jsonb;
  -- questions of one voting
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x where x.set_id = (a->>'set')::uuid), '[]'::jsonb);
  elsif p_action = 'create' then
    v_set := (a->>'set')::uuid;
    if not exists (select 1 from public.poll_sets where id = v_set) then raise exception 'Balsavimas nerastas'; end if;
    insert into public.polls (set_id, topic, question, options, duration_sec, multi, sort, created_by)
      values (v_set, left(coalesce(a->>'topic', ''), 200), left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb),
              coalesce((a->>'duration_sec')::int, 60), coalesce((a->>'multi')::boolean, false),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls where set_id = v_set)), auth.uid())
      returning * into p;
    return to_jsonb(p);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    insert into public.poll_assets (mime, data, bytes) values (a->>'mime', a->>'data', length(a->>'data') * 3 / 4) returning id into v_new;
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        topic = left(coalesce(a->>'topic', topic), 200), question = left(coalesce(a->>'question', question), 500),
        options = coalesce(a->'options', options), duration_sec = coalesce((a->>'duration_sec')::int, duration_sec),
        multi = coalesce((a->>'multi')::boolean, multi), sort = coalesce((a->>'sort')::int, sort), updated_at = now()
      where id = v_id returning * into p;
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'stop' then
    p := public.poll_do_stop(v_id);
  else
    raise exception 'Nežinomas veiksmas';
  end if;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return to_jsonb(p);
end $$;
revoke all on function public.poll_admin(text, text, jsonb) from public;
grant execute on function public.poll_admin(text, text, jsonb) to anon, authenticated;


-- ============================================================
-- Balsavimai, 6 dalis (paleisti po polls5.sql): rezultatų ekranas
-- gauna balsavimo QR kodo raktą – QR rodomas laukiant naujo klausimo
-- ir šalia laikrodžio, kol vyksta balsavimas.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  s := (select x from public.poll_sets x where x.results_token = p_token);
  if s.id is not null then
    perm := true;
    p := public.poll_set_current(s.id);
    if p.id is null then p := (select x from public.polls x where x.set_id = s.id and x.ends_at <= now() order by x.ends_at desc limit 1); end if;
  else
    p := (select x from public.polls x where x.results_token = p_token);
    if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'vote_token', case when perm then s.vote_token end,
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
grant execute on function public.poll_results(text) to anon, authenticated;


-- ============================================================
-- Balsavimai, 7 dalis (paleisti po polls6.sql):
--  * „Parodyti nominantus“ – rezultatų ekrane tema, klausimas ir visi
--    atsakymų variantai (be QR kodo ir be balsavimo)
--  * „Parodyti nugalėtoją“ – iš anksto pažymėtas nugalėtojas (varnelė prie
--    atsakymo) parodomas su fejerverkais, be balsavimo
--  * iš anksto pažymėtas nugalėtojas niekur viešai nerodomas, kol jo neparodai
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

alter table public.poll_sets add column if not exists display jsonb;

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  s := (select x from public.poll_sets x where x.results_token = p_token);
  if s.id is not null then
    perm := true;
    -- nominees / the winner chosen beforehand
    if s.display is not null then
      p := (select x from public.polls x where x.id = (s.display->>'poll')::uuid and x.set_id = s.id);
      if p.id is not null then
        return jsonb_build_object('state', case when s.display->>'mode' = 'winner' then 'reveal' else 'nominees' end, 'now', now(),
          'poll', p.id, 'round', p.round, 'at', s.display->>'at', 'topic', nullif(p.topic, ''), 'question', p.question,
          'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                        'winner', s.display->>'mode' = 'winner' and coalesce(o->>'winner', '') = 'true') order by n), '[]'::jsonb)
                      from jsonb_array_elements(p.options) with ordinality as x(o, n)));
      end if;
    end if;
    p := public.poll_set_current(s.id);
    if p.id is null then p := (select x from public.polls x where x.set_id = s.id and x.ends_at <= now() order by x.ends_at desc limit 1); end if;
  else
    p := (select x from public.polls x where x.results_token = p_token);
    if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'vote_token', case when perm then s.vote_token end,
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
grant execute on function public.poll_results(text) to anon, authenticated;

-- the editor (admin, or anyone with the editor link)
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; s public.poll_sets; v_id uuid; v_new uuid; v_set uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  -- votings
  if p_action = 'sets' then
    return coalesce((select jsonb_agg(to_jsonb(x) || jsonb_build_object(
              'questions', (select count(*) from public.polls q where q.set_id = x.id),
              'live', (select count(*) from public.polls q where q.set_id = x.id and q.ends_at > now()))
            order by x.created_at desc) from public.poll_sets x), '[]'::jsonb);
  elsif p_action = 'set_create' then
    v_new := gen_random_uuid();
    insert into public.poll_sets (id, name) values (v_new, left(coalesce(nullif(trim(a->>'name'), ''), 'Balsavimas'), 200));
    return (select to_jsonb(x) from public.poll_sets x where x.id = v_new);
  elsif p_action = 'set_update' then
    update public.poll_sets set
        name = left(coalesce(nullif(trim(a->>'name'), ''), name), 200), brand = coalesce(a->'brand', brand),
        results_w = greatest(100, least(8000, coalesce((a->>'results_w')::int, results_w))),
        results_h = greatest(100, least(8000, coalesce((a->>'results_h')::int, results_h))),
        show_all = coalesce((a->>'show_all')::boolean, show_all), updated_at = now()
      where id = (a->>'id')::uuid;
    s := (select x from public.poll_sets x where x.id = (a->>'id')::uuid);
    if s.id is null then raise exception 'Balsavimas nerastas'; end if;
    return to_jsonb(s);
  elsif p_action = 'set_get' then
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'id')::uuid);
  elsif p_action = 'hide' then
    update public.poll_sets set display = null, updated_at = now() where id = (a->>'set')::uuid;
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'set')::uuid);
  elsif p_action = 'set_delete' then
    delete from public.poll_sets where id = (a->>'id')::uuid;
    return '{}'::jsonb;
  -- questions of one voting
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x where x.set_id = (a->>'set')::uuid), '[]'::jsonb);
  elsif p_action = 'create' then
    v_set := (a->>'set')::uuid;
    if not exists (select 1 from public.poll_sets where id = v_set) then raise exception 'Balsavimas nerastas'; end if;
    v_new := gen_random_uuid();
    insert into public.polls (id, set_id, topic, question, options, duration_sec, multi, sort, created_by)
      values (v_new, v_set, left(coalesce(a->>'topic', ''), 200), left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb),
              coalesce((a->>'duration_sec')::int, 60), coalesce((a->>'multi')::boolean, false),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls where set_id = v_set)), auth.uid());
    return (select to_jsonb(x) from public.polls x where x.id = v_new);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    v_new := gen_random_uuid();
    insert into public.poll_assets (id, mime, data, bytes) values (v_new, a->>'mime', a->>'data', length(a->>'data') * 3 / 4);
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        topic = left(coalesce(a->>'topic', topic), 200), question = left(coalesce(a->>'question', question), 500),
        options = coalesce(a->'options', options), duration_sec = coalesce((a->>'duration_sec')::int, duration_sec),
        multi = coalesce((a->>'multi')::boolean, multi), sort = coalesce((a->>'sort')::int, sort), updated_at = now()
      where id = v_id;
    p := (select x from public.polls x where x.id = v_id);
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    update public.poll_sets set display = null where id = (select q.set_id from public.polls q where q.id = v_id);
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'show' then
    -- the results screen shows this question's nominees, or its winner chosen beforehand (no voting)
    p := (select x from public.polls x where x.id = v_id);
    if p.id is null then raise exception 'Klausimas nerastas'; end if;
    if a->>'mode' = 'winner' and not exists (select 1 from jsonb_array_elements(p.options) o where o->>'winner' = 'true') then
      raise exception 'Nugalėtojas nepažymėtas'; end if;
    update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
      where set_id = p.set_id and ends_at > now();
    update public.poll_sets set display = jsonb_build_object('mode', case when a->>'mode' = 'winner' then 'winner' else 'nominees' end, 'poll', p.id, 'at', now()),
        updated_at = now()
      where id = p.set_id;
    return (select to_jsonb(x) from public.poll_sets x where x.id = p.set_id);
  elsif p_action = 'stop' then
    p := public.poll_do_stop(v_id);
  else
    raise exception 'Nežinomas veiksmas';
  end if;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return to_jsonb(p);
end $$;
revoke all on function public.poll_admin(text, text, jsonb) from public;
grant execute on function public.poll_admin(text, text, jsonb) to anon, authenticated;


-- ============================================================
-- Balsavimai, 8 dalis (paleisti po polls7.sql): UŽSKLANDOS
--  * tarp klausimų galima įterpti užsklandą (polls.kind = 'splash'):
--    tema, savas fonas, šriftas, spalvos, logotipas (dydžiai, vietos)
--  * ▶ prie užsklandos – rezultatų ekrane rodoma tik užsklanda
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

alter table public.polls add column if not exists kind text not null default 'question';
alter table public.poll_sets add column if not exists display jsonb;

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  s := (select x from public.poll_sets x where x.results_token = p_token);
  if s.id is not null then
    perm := true;
    -- nominees / the winner chosen beforehand
    if s.display is not null then
      p := (select x from public.polls x where x.id = (s.display->>'poll')::uuid and x.set_id = s.id);
      if p.id is not null and s.display->>'mode' = 'splash' then
        return jsonb_build_object('state', 'splash', 'now', now(), 'poll', p.id, 'at', s.display->>'at', 'topic', nullif(p.topic, ''),
          'splash', p.brand, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all);
      end if;
      if p.id is not null then
        return jsonb_build_object('state', case when s.display->>'mode' = 'winner' then 'reveal' else 'nominees' end, 'now', now(),
          'poll', p.id, 'round', p.round, 'at', s.display->>'at', 'topic', nullif(p.topic, ''), 'question', p.question,
          'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                        'winner', s.display->>'mode' = 'winner' and coalesce(o->>'winner', '') = 'true') order by n), '[]'::jsonb)
                      from jsonb_array_elements(p.options) with ordinality as x(o, n)));
      end if;
    end if;
    p := public.poll_set_current(s.id);
    if p.id is null then p := (select x from public.polls x where x.set_id = s.id and x.ends_at <= now() order by x.ends_at desc limit 1); end if;
  else
    p := (select x from public.polls x where x.results_token = p_token);
    if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'vote_token', case when perm then s.vote_token end,
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
grant execute on function public.poll_results(text) to anon, authenticated;

-- the editor (admin, or anyone with the editor link)
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; s public.poll_sets; v_id uuid; v_new uuid; v_set uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  -- votings
  if p_action = 'sets' then
    return coalesce((select jsonb_agg(to_jsonb(x) || jsonb_build_object(
              'questions', (select count(*) from public.polls q where q.set_id = x.id and q.kind <> 'splash'),
              'live', (select count(*) from public.polls q where q.set_id = x.id and q.ends_at > now()))
            order by x.created_at desc) from public.poll_sets x), '[]'::jsonb);
  elsif p_action = 'set_create' then
    v_new := gen_random_uuid();
    insert into public.poll_sets (id, name) values (v_new, left(coalesce(nullif(trim(a->>'name'), ''), 'Balsavimas'), 200));
    return (select to_jsonb(x) from public.poll_sets x where x.id = v_new);
  elsif p_action = 'set_update' then
    update public.poll_sets set
        name = left(coalesce(nullif(trim(a->>'name'), ''), name), 200), brand = coalesce(a->'brand', brand),
        results_w = greatest(100, least(8000, coalesce((a->>'results_w')::int, results_w))),
        results_h = greatest(100, least(8000, coalesce((a->>'results_h')::int, results_h))),
        show_all = coalesce((a->>'show_all')::boolean, show_all), updated_at = now()
      where id = (a->>'id')::uuid;
    s := (select x from public.poll_sets x where x.id = (a->>'id')::uuid);
    if s.id is null then raise exception 'Balsavimas nerastas'; end if;
    return to_jsonb(s);
  elsif p_action = 'set_get' then
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'id')::uuid);
  elsif p_action = 'hide' then
    update public.poll_sets set display = null, updated_at = now() where id = (a->>'set')::uuid;
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'set')::uuid);
  elsif p_action = 'set_delete' then
    delete from public.poll_sets where id = (a->>'id')::uuid;
    return '{}'::jsonb;
  -- questions of one voting
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x where x.set_id = (a->>'set')::uuid), '[]'::jsonb);
  elsif p_action = 'create' then
    v_set := (a->>'set')::uuid;
    if not exists (select 1 from public.poll_sets where id = v_set) then raise exception 'Balsavimas nerastas'; end if;
    v_new := gen_random_uuid();
    insert into public.polls (id, set_id, kind, brand, topic, question, options, duration_sec, multi, sort, created_by)
      values (v_new, v_set, case when a->>'kind' = 'splash' then 'splash' else 'question' end, coalesce(a->'brand', '{}'::jsonb),
              left(coalesce(a->>'topic', ''), 200), left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb),
              coalesce((a->>'duration_sec')::int, 60), coalesce((a->>'multi')::boolean, false),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls where set_id = v_set)), auth.uid());
    return (select to_jsonb(x) from public.polls x where x.id = v_new);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    v_new := gen_random_uuid();
    insert into public.poll_assets (id, mime, data, bytes) values (v_new, a->>'mime', a->>'data', length(a->>'data') * 3 / 4);
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        topic = left(coalesce(a->>'topic', topic), 200), question = left(coalesce(a->>'question', question), 500),
        options = coalesce(a->'options', options), duration_sec = coalesce((a->>'duration_sec')::int, duration_sec),
        multi = coalesce((a->>'multi')::boolean, multi), sort = coalesce((a->>'sort')::int, sort),
        brand = case when kind = 'splash' then coalesce(a->'brand', brand) else brand end, updated_at = now()
      where id = v_id;
    p := (select x from public.polls x where x.id = v_id);
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    if exists (select 1 from public.polls q where q.id = v_id and q.kind = 'splash') then raise exception 'Užsklanda nėra balsavimas'; end if;
    update public.poll_sets set display = null where id = (select q.set_id from public.polls q where q.id = v_id);
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'show' then
    -- the results screen shows this question's nominees, or its winner chosen beforehand (no voting)
    p := (select x from public.polls x where x.id = v_id);
    if p.id is null then raise exception 'Klausimas nerastas'; end if;
    if (a->>'mode' = 'splash') <> (p.kind = 'splash') then raise exception 'Netinkamas rodymas'; end if;
    if a->>'mode' = 'winner' and not exists (select 1 from jsonb_array_elements(p.options) o where o->>'winner' = 'true') then
      raise exception 'Nugalėtojas nepažymėtas'; end if;
    update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
      where set_id = p.set_id and ends_at > now();
    update public.poll_sets set display = jsonb_build_object('mode', case when a->>'mode' in ('winner', 'splash') then a->>'mode' else 'nominees' end, 'poll', p.id, 'at', now()),
        updated_at = now()
      where id = p.set_id;
    return (select to_jsonb(x) from public.poll_sets x where x.id = p.set_id);
  elsif p_action = 'stop' then
    p := public.poll_do_stop(v_id);
  else
    raise exception 'Nežinomas veiksmas';
  end if;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return to_jsonb(p);
end $$;
revoke all on function public.poll_admin(text, text, jsonb) from public;
grant execute on function public.poll_admin(text, text, jsonb) to anon, authenticated;


-- ============================================================
-- Balsavimai, 9 dalis (paleisti po polls8.sql): ĮRAŠOMA NOMINACIJA
--  * nominacijos tipas „Žmonės įrašo patys“ (polls.kind = 'write'):
--    nuskaitęs QR kodą žmogus įrašo vardą ir pavardę (vieną arba iki
--    write_max skirtingų); pasibaigus laikui suskaičiuojama, kuris
--    įrašytas daugiausiai kartų (didžiosios / mažosios raidės ir tarpai
--    nesvarbu)
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

alter table public.polls add column if not exists kind text not null default 'question';
alter table public.polls add column if not exists write_max int not null default 1;
alter table public.poll_sets add column if not exists display jsonb;
alter table public.poll_votes add column if not exists entry text;

-- the voter's page: also says whether names are typed and how many
create or replace function public.poll_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; st text; s public.poll_sets;
begin
  s := (select x from public.poll_sets x where x.vote_token = p_token);
  if s.id is not null then p := public.poll_set_current(s.id);
  else p := (select x from public.polls x where x.vote_token = p_token);
       if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if; end if;
  if p.id is null then return jsonb_build_object('state', case when s.id is not null then 'idle' else 'invalid' end, 'now', now(), 'brand', coalesce(s.brand, '{}'::jsonb)); end if;
  st := public.poll_state(p);
  if s.id is not null and p_token = s.vote_token and st not in ('waiting', 'live') then st := 'idle'; end if;
  return jsonb_build_object('state', st, 'now', now(), 'poll', p.id, 'round', p.round, 'starts_at', p.starts_at, 'ends_at', p.ends_at,
    'brand', coalesce(s.brand, p.brand), 'multi', p.multi, 'write', p.kind = 'write', 'write_max', p.write_max,
    'topic', case when st in ('waiting', 'live') then nullif(p.topic, '') end,
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' and p.kind <> 'write' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;
grant execute on function public.poll_public(text) to anon, authenticated;

-- typed names: one submission per phone, up to write_max different names
create or replace function public.poll_write(p_token text, p_names text[], p_voter text, p_poll uuid) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; ks text[]; es text[]; n int;
begin
  s := (select x from public.poll_sets x where x.vote_token = p_token);
  if s.id is not null then p := (select x from public.polls x where x.id = p_poll and x.set_id = s.id);
  else p := (select x from public.polls x where x.vote_token = p_token); end if;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if p.kind <> 'write' or coalesce(length(p_voter), 0) not between 8 and 100 then return 'bad'; end if;
  -- the same name twice (letter case, spaces) counts once
  ks := (select array_agg(z.k order by z.k) from (select distinct on (lower(t)) 'w:' || lower(t) k, t e
           from (select left(regexp_replace(btrim(x), '\s+', ' ', 'g'), 80) t from unnest(coalesce(p_names, '{}'::text[])) x) y
          where t <> '' order by lower(t), t) z);
  es := (select array_agg(z.e order by z.k) from (select distinct on (lower(t)) 'w:' || lower(t) k, t e
           from (select left(regexp_replace(btrim(x), '\s+', ' ', 'g'), 80) t from unnest(coalesce(p_names, '{}'::text[])) x) y
          where t <> '' order by lower(t), t) z);
  n := coalesce(array_length(ks, 1), 0);
  if n = 0 then return 'bad'; end if;
  if n > p.write_max then return 'limit'; end if;
  perform pg_advisory_xact_lock(hashtext(p.id::text || ':' || p_voter));
  if exists (select 1 from public.poll_votes where poll_id = p.id and round = p.round and voter = p_voter) then return 'already'; end if;
  insert into public.poll_votes (poll_id, round, option_id, voter, entry) select p.id, p.round, ks[i], p_voter, es[i] from generate_subscripts(ks, 1) i;
  return 'ok';
end $$;
revoke all on function public.poll_write(text, text[], text, uuid) from public;
grant execute on function public.poll_write(text, text[], text, uuid) to anon, authenticated;

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  s := (select x from public.poll_sets x where x.results_token = p_token);
  if s.id is not null then
    perm := true;
    -- nominees / the winner chosen beforehand
    if s.display is not null then
      p := (select x from public.polls x where x.id = (s.display->>'poll')::uuid and x.set_id = s.id);
      if p.id is not null and s.display->>'mode' = 'splash' then
        return jsonb_build_object('state', 'splash', 'now', now(), 'poll', p.id, 'at', s.display->>'at', 'topic', nullif(p.topic, ''),
          'splash', p.brand, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all);
      end if;
      if p.id is not null then
        return jsonb_build_object('state', case when s.display->>'mode' = 'winner' then 'reveal' else 'nominees' end, 'now', now(),
          'poll', p.id, 'round', p.round, 'at', s.display->>'at', 'topic', nullif(p.topic, ''), 'question', p.question,
          'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                        'winner', s.display->>'mode' = 'winner' and coalesce(o->>'winner', '') = 'true') order by n), '[]'::jsonb)
                      from jsonb_array_elements(p.options) with ordinality as x(o, n)));
      end if;
    end if;
    p := public.poll_set_current(s.id);
    if p.id is null then p := (select x from public.polls x where x.set_id = s.id and x.ends_at <= now() order by x.ends_at desc limit 1); end if;
  else
    p := (select x from public.polls x where x.results_token = p_token);
    if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'vote_token', case when perm then s.vote_token end,
    'write', p.kind = 'write',
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', case when p.kind = 'write' then
                 -- names typed by the voters: the same name (letter case and spaces aside) counts together,
                 -- shown as it was typed most often; the 15 most written
                 (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'votes', z.n) order by z.n desc, z.t), '[]'::jsonb) from (
                    select v.option_id k, count(*) n,
                           (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                              group by v2.entry order by count(*) desc, v2.entry limit 1) t
                      from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                      group by v.option_id order by count(*) desc, v.option_id limit 15) z)
               else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
end $$;
grant execute on function public.poll_results(text) to anon, authenticated;

-- the editor (admin, or anyone with the editor link)
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; s public.poll_sets; v_id uuid; v_new uuid; v_set uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  -- votings
  if p_action = 'sets' then
    return coalesce((select jsonb_agg(to_jsonb(x) || jsonb_build_object(
              'questions', (select count(*) from public.polls q where q.set_id = x.id and q.kind <> 'splash'),
              'live', (select count(*) from public.polls q where q.set_id = x.id and q.ends_at > now()))
            order by x.created_at desc) from public.poll_sets x), '[]'::jsonb);
  elsif p_action = 'set_create' then
    v_new := gen_random_uuid();
    insert into public.poll_sets (id, name) values (v_new, left(coalesce(nullif(trim(a->>'name'), ''), 'Balsavimas'), 200));
    return (select to_jsonb(x) from public.poll_sets x where x.id = v_new);
  elsif p_action = 'set_update' then
    update public.poll_sets set
        name = left(coalesce(nullif(trim(a->>'name'), ''), name), 200), brand = coalesce(a->'brand', brand),
        results_w = greatest(100, least(8000, coalesce((a->>'results_w')::int, results_w))),
        results_h = greatest(100, least(8000, coalesce((a->>'results_h')::int, results_h))),
        show_all = coalesce((a->>'show_all')::boolean, show_all), updated_at = now()
      where id = (a->>'id')::uuid;
    s := (select x from public.poll_sets x where x.id = (a->>'id')::uuid);
    if s.id is null then raise exception 'Balsavimas nerastas'; end if;
    return to_jsonb(s);
  elsif p_action = 'set_get' then
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'id')::uuid);
  elsif p_action = 'hide' then
    update public.poll_sets set display = null, updated_at = now() where id = (a->>'set')::uuid;
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'set')::uuid);
  elsif p_action = 'set_delete' then
    delete from public.poll_sets where id = (a->>'id')::uuid;
    return '{}'::jsonb;
  -- questions of one voting
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x where x.set_id = (a->>'set')::uuid), '[]'::jsonb);
  elsif p_action = 'create' then
    v_set := (a->>'set')::uuid;
    if not exists (select 1 from public.poll_sets where id = v_set) then raise exception 'Balsavimas nerastas'; end if;
    v_new := gen_random_uuid();
    insert into public.polls (id, set_id, kind, brand, topic, question, options, duration_sec, multi, sort, created_by)
      values (v_new, v_set, case when a->>'kind' in ('splash', 'write') then a->>'kind' else 'question' end, coalesce(a->'brand', '{}'::jsonb),
              left(coalesce(a->>'topic', ''), 200), left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb),
              coalesce((a->>'duration_sec')::int, 60), coalesce((a->>'multi')::boolean, false),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls where set_id = v_set)), auth.uid());
    update public.polls set write_max = greatest(1, least(50, coalesce((a->>'write_max')::int, 1))) where id = v_new;
    return (select to_jsonb(x) from public.polls x where x.id = v_new);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    v_new := gen_random_uuid();
    insert into public.poll_assets (id, mime, data, bytes) values (v_new, a->>'mime', a->>'data', length(a->>'data') * 3 / 4);
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        topic = left(coalesce(a->>'topic', topic), 200), question = left(coalesce(a->>'question', question), 500),
        options = coalesce(a->'options', options), duration_sec = coalesce((a->>'duration_sec')::int, duration_sec),
        multi = coalesce((a->>'multi')::boolean, multi), sort = coalesce((a->>'sort')::int, sort),
        brand = case when kind = 'splash' then coalesce(a->'brand', brand) else brand end,
        kind = case when kind <> 'splash' and a->>'kind' in ('question', 'write') then a->>'kind' else kind end,
        write_max = greatest(1, least(50, coalesce((a->>'write_max')::int, write_max))), updated_at = now()
      where id = v_id;
    p := (select x from public.polls x where x.id = v_id);
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    if exists (select 1 from public.polls q where q.id = v_id and q.kind = 'splash') then raise exception 'Užsklanda nėra balsavimas'; end if;
    update public.poll_sets set display = null where id = (select q.set_id from public.polls q where q.id = v_id);
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'show' then
    -- the results screen shows this question's nominees, or its winner chosen beforehand (no voting)
    p := (select x from public.polls x where x.id = v_id);
    if p.id is null then raise exception 'Klausimas nerastas'; end if;
    if (a->>'mode' = 'splash') <> (p.kind = 'splash') then raise exception 'Netinkamas rodymas'; end if;
    if a->>'mode' = 'winner' and not exists (select 1 from jsonb_array_elements(p.options) o where o->>'winner' = 'true') then
      raise exception 'Nugalėtojas nepažymėtas'; end if;
    update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
      where set_id = p.set_id and ends_at > now();
    update public.poll_sets set display = jsonb_build_object('mode', case when a->>'mode' in ('winner', 'splash') then a->>'mode' else 'nominees' end, 'poll', p.id, 'at', now()),
        updated_at = now()
      where id = p.set_id;
    return (select to_jsonb(x) from public.poll_sets x where x.id = p.set_id);
  elsif p_action = 'stop' then
    p := public.poll_do_stop(v_id);
  else
    raise exception 'Nežinomas veiksmas';
  end if;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return to_jsonb(p);
end $$;
revoke all on function public.poll_admin(text, text, jsonb) from public;
grant execute on function public.poll_admin(text, text, jsonb) to anon, authenticated;


-- ============================================================
-- Balsavimai, 10 dalis (paleisti po polls9.sql): ĮRAŠOMOS NOMINACIJOS
-- NUGALĖTOJAS – TIK PASPAUDUS MYGTUKĄ
--  * pasibaigus laikui rezultatų ekranas rodo „Balsavimas baigėsi“
--    (nugalėtojas nesiunčiamas net rezultatų nuorodai)
--  * „Parodyti nugalėtoją“ – daugiausiai kartų įrašytas vardas
--    (lygiųjų atveju – visi) su fejerverkais
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  s := (select x from public.poll_sets x where x.results_token = p_token);
  if s.id is not null then
    perm := true;
    -- nominees / the winner chosen beforehand
    if s.display is not null then
      p := (select x from public.polls x where x.id = (s.display->>'poll')::uuid and x.set_id = s.id);
      if p.id is not null and s.display->>'mode' = 'splash' then
        return jsonb_build_object('state', 'splash', 'now', now(), 'poll', p.id, 'at', s.display->>'at', 'topic', nullif(p.topic, ''),
          'splash', p.brand, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all);
      end if;
      if p.id is not null then
        return jsonb_build_object('state', case when s.display->>'mode' = 'winner' then 'reveal' else 'nominees' end, 'now', now(),
          'poll', p.id, 'round', p.round, 'at', s.display->>'at', 'topic', nullif(p.topic, ''), 'question', p.question,
          'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          'options', case when p.kind = 'write' then
                        -- typed names: the most written one(s) win, shown only now
                        (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'winner', s.display->>'mode' = 'winner' and z.n = z.m) order by z.n desc, z.t), '[]'::jsonb) from (
                           select v.option_id k, count(*) n, max(count(*)) over () m,
                                  (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                                     group by v2.entry order by count(*) desc, v2.entry limit 1) t
                             from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                             group by v.option_id order by count(*) desc, v.option_id limit 15) z)
                      else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                        'winner', s.display->>'mode' = 'winner' and coalesce(o->>'winner', '') = 'true') order by n), '[]'::jsonb)
                      from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
      end if;
    end if;
    p := public.poll_set_current(s.id);
    if p.id is null then p := (select x from public.polls x where x.set_id = s.id and x.ends_at <= now() order by x.ends_at desc limit 1); end if;
  else
    p := (select x from public.polls x where x.results_token = p_token);
    if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  -- typed names on the voting's screen: when the time is up only "voting ended" – the winner waits for the editor's button
  if perm and p.kind = 'write' and public.poll_state(p) = 'ended' then
    return jsonb_build_object('state', 'ended', 'hold', true, 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
      'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', s.brand, 'multi', p.multi, 'write', true,
      'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token, 'total', 0, 'options', '[]'::jsonb);
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'vote_token', case when perm then s.vote_token end,
    'write', p.kind = 'write',
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', case when p.kind = 'write' then
                 -- names typed by the voters: the same name (letter case and spaces aside) counts together,
                 -- shown as it was typed most often; the 15 most written
                 (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'votes', z.n) order by z.n desc, z.t), '[]'::jsonb) from (
                    select v.option_id k, count(*) n,
                           (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                              group by v2.entry order by count(*) desc, v2.entry limit 1) t
                      from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                      group by v.option_id order by count(*) desc, v.option_id limit 15) z)
               else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
end $$;
grant execute on function public.poll_results(text) to anon, authenticated;

-- the editor (admin, or anyone with the editor link)
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; s public.poll_sets; v_id uuid; v_new uuid; v_set uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  -- votings
  if p_action = 'sets' then
    return coalesce((select jsonb_agg(to_jsonb(x) || jsonb_build_object(
              'questions', (select count(*) from public.polls q where q.set_id = x.id and q.kind <> 'splash'),
              'live', (select count(*) from public.polls q where q.set_id = x.id and q.ends_at > now()))
            order by x.created_at desc) from public.poll_sets x), '[]'::jsonb);
  elsif p_action = 'set_create' then
    v_new := gen_random_uuid();
    insert into public.poll_sets (id, name) values (v_new, left(coalesce(nullif(trim(a->>'name'), ''), 'Balsavimas'), 200));
    return (select to_jsonb(x) from public.poll_sets x where x.id = v_new);
  elsif p_action = 'set_update' then
    update public.poll_sets set
        name = left(coalesce(nullif(trim(a->>'name'), ''), name), 200), brand = coalesce(a->'brand', brand),
        results_w = greatest(100, least(8000, coalesce((a->>'results_w')::int, results_w))),
        results_h = greatest(100, least(8000, coalesce((a->>'results_h')::int, results_h))),
        show_all = coalesce((a->>'show_all')::boolean, show_all), updated_at = now()
      where id = (a->>'id')::uuid;
    s := (select x from public.poll_sets x where x.id = (a->>'id')::uuid);
    if s.id is null then raise exception 'Balsavimas nerastas'; end if;
    return to_jsonb(s);
  elsif p_action = 'set_get' then
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'id')::uuid);
  elsif p_action = 'hide' then
    update public.poll_sets set display = null, updated_at = now() where id = (a->>'set')::uuid;
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'set')::uuid);
  elsif p_action = 'set_delete' then
    delete from public.poll_sets where id = (a->>'id')::uuid;
    return '{}'::jsonb;
  -- questions of one voting
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x where x.set_id = (a->>'set')::uuid), '[]'::jsonb);
  elsif p_action = 'create' then
    v_set := (a->>'set')::uuid;
    if not exists (select 1 from public.poll_sets where id = v_set) then raise exception 'Balsavimas nerastas'; end if;
    v_new := gen_random_uuid();
    insert into public.polls (id, set_id, kind, brand, topic, question, options, duration_sec, multi, sort, created_by)
      values (v_new, v_set, case when a->>'kind' in ('splash', 'write') then a->>'kind' else 'question' end, coalesce(a->'brand', '{}'::jsonb),
              left(coalesce(a->>'topic', ''), 200), left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb),
              coalesce((a->>'duration_sec')::int, 60), coalesce((a->>'multi')::boolean, false),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls where set_id = v_set)), auth.uid());
    update public.polls set write_max = greatest(1, least(50, coalesce((a->>'write_max')::int, 1))) where id = v_new;
    return (select to_jsonb(x) from public.polls x where x.id = v_new);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    v_new := gen_random_uuid();
    insert into public.poll_assets (id, mime, data, bytes) values (v_new, a->>'mime', a->>'data', length(a->>'data') * 3 / 4);
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        topic = left(coalesce(a->>'topic', topic), 200), question = left(coalesce(a->>'question', question), 500),
        options = coalesce(a->'options', options), duration_sec = coalesce((a->>'duration_sec')::int, duration_sec),
        multi = coalesce((a->>'multi')::boolean, multi), sort = coalesce((a->>'sort')::int, sort),
        brand = case when kind = 'splash' then coalesce(a->'brand', brand) else brand end,
        kind = case when kind <> 'splash' and a->>'kind' in ('question', 'write') then a->>'kind' else kind end,
        write_max = greatest(1, least(50, coalesce((a->>'write_max')::int, write_max))), updated_at = now()
      where id = v_id;
    p := (select x from public.polls x where x.id = v_id);
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    if exists (select 1 from public.polls q where q.id = v_id and q.kind = 'splash') then raise exception 'Užsklanda nėra balsavimas'; end if;
    update public.poll_sets set display = null where id = (select q.set_id from public.polls q where q.id = v_id);
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'show' then
    -- the results screen shows this question's nominees, or its winner chosen beforehand (no voting)
    p := (select x from public.polls x where x.id = v_id);
    if p.id is null then raise exception 'Klausimas nerastas'; end if;
    if (a->>'mode' = 'splash') <> (p.kind = 'splash') then raise exception 'Netinkamas rodymas'; end if;
    if a->>'mode' = 'winner' and p.kind = 'write' and not exists (select 1 from public.poll_votes v where v.poll_id = p.id and v.round = p.round) then
      raise exception 'Dar niekas neįrašė vardo'; end if;
    if a->>'mode' = 'winner' and p.kind <> 'write' and not exists (select 1 from jsonb_array_elements(p.options) o where o->>'winner' = 'true') then
      raise exception 'Nugalėtojas nepažymėtas'; end if;
    update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
      where set_id = p.set_id and ends_at > now();
    update public.poll_sets set display = jsonb_build_object('mode', case when a->>'mode' in ('winner', 'splash') then a->>'mode' else 'nominees' end, 'poll', p.id, 'at', now()),
        updated_at = now()
      where id = p.set_id;
    return (select to_jsonb(x) from public.poll_sets x where x.id = p.set_id);
  elsif p_action = 'stop' then
    p := public.poll_do_stop(v_id);
  else
    raise exception 'Nežinomas veiksmas';
  end if;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return to_jsonb(p);
end $$;
revoke all on function public.poll_admin(text, text, jsonb) from public;
grant execute on function public.poll_admin(text, text, jsonb) to anon, authenticated;


-- ============================================================
-- Balsavimai, 11 dalis (paleisti po polls10.sql): ĮRAŠOMI VARDAI
--  * tas pats vardas vienam žmogui – tik kartą (ir labai panašus)
--  * labai panašus į jau įrašytą vardas priskiriamas jam, pvz.
--    „Vardas Vardeni“ → „Vardas Vardenis“. Panašu, kai: lietuviškos raidės,
--    didžiosios raidės, tarpai ir skyrybos ženklai nesvarbūs, žodžiai gali
--    būti sukeisti; kiekviename žodyje 1 klaida (ilguose, nuo 9 raidžių – 2),
--    pirmoji raidė ta pati, trumpi žodžiai (iki 4 raidžių) – tik tiksliai
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

-- letters only, without Lithuanian (and other) accents: „Vardėnis  VARDAS“ → „vardenis vardas“
create or replace function public.poll_name_norm(t text) returns text language sql immutable as $$
  select btrim(regexp_replace(regexp_replace(translate(lower(coalesce(t, '')), 'ąčęėįšųūžáàäâãåçéèêëíìîïñóòöôõúùûüýÿłńśźż', 'aceeisuuzaaaaaaceeeeiiiinooooouuuuyylnszz'), '[^a-z0-9 ]', ' ', 'g'), '\s+', ' ', 'g'))
$$;

-- edit distance: letters to add, remove or change; two neighbouring letters swapped count as one
create or replace function public.poll_lev(a text, b text) returns int language plpgsql immutable as $$
declare la int := length(a); lb int := length(b); pp int[]; prev int[]; cur int[]; i int; j int; c int; v int;
begin
  if a = b then return 0; end if;
  if la = 0 then return lb; end if;
  if lb = 0 then return la; end if;
  prev := array(select generate_series(0, lb));
  for i in 1..la loop
    cur := array[i];
    for j in 1..lb loop
      c := case when substr(a, i, 1) = substr(b, j, 1) then 0 else 1 end;
      v := least(prev[j + 1] + 1, cur[j] + 1, prev[j] + c);
      if i > 1 and j > 1 and substr(a, i, 1) = substr(b, j - 1, 1) and substr(a, i - 1, 1) = substr(b, j, 1) then v := least(v, pp[j - 1] + 1); end if;
      cur := cur || v;
    end loop;
    pp := prev; prev := cur;
  end loop;
  return prev[lb + 1];
end $$;

-- two words are the same name word: equal, or a small typo with the same first letter
create or replace function public.poll_word_near(x text, y text) returns boolean language sql immutable as $$
  select x = y or (left(x, 1) = left(y, 1) and greatest(length(x), length(y)) > 4
    and public.poll_lev(x, y) <= case when greatest(length(x), length(y)) <= 8 then 1 else 2 end)
$$;

-- two names (already normalized) are the same person: the same number of words, each near – in order or swapped
create or replace function public.poll_name_near(a text, b text) returns boolean language plpgsql immutable as $$
declare wa text[] := string_to_array(a, ' '); wb text[] := string_to_array(b, ' '); sa text[]; sb text[]; i int; ok boolean;
begin
  if a = b then return true; end if;
  if coalesce(array_length(wa, 1), 0) = 0 or coalesce(array_length(wa, 1), 0) <> coalesce(array_length(wb, 1), 0) then return false; end if;
  ok := true;
  for i in 1..array_length(wa, 1) loop
    if not public.poll_word_near(wa[i], wb[i]) then ok := false; exit; end if;
  end loop;
  if ok then return true; end if;
  sa := array(select w from unnest(wa) w order by w);
  sb := array(select w from unnest(wb) w order by w);
  for i in 1..array_length(sa, 1) loop
    if not public.poll_word_near(sa[i], sb[i]) then return false; end if;
  end loop;
  return true;
end $$;

-- typed names: one submission per phone, up to write_max different names;
-- a name near one already written counts for it; the same name twice in one submission – 'dup'
create or replace function public.poll_write(p_token text, p_names text[], p_voter text, p_poll uuid) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; t text; nm text; k text; ks text[] := '{}'; es text[] := '{}';
begin
  s := (select x from public.poll_sets x where x.vote_token = p_token);
  if s.id is not null then p := (select x from public.polls x where x.id = p_poll and x.set_id = s.id);
  else p := (select x from public.polls x where x.vote_token = p_token); end if;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if p.kind <> 'write' or coalesce(length(p_voter), 0) not between 8 and 100 then return 'bad'; end if;
  -- one name at a time for this nomination, so near names written at the same moment still meet
  perform pg_advisory_xact_lock(hashtext('poll_write:' || p.id::text));
  if exists (select 1 from public.poll_votes where poll_id = p.id and round = p.round and voter = p_voter) then return 'already'; end if;
  foreach t in array coalesce(p_names, '{}'::text[]) loop
    t := left(regexp_replace(btrim(coalesce(t, '')), '\s+', ' ', 'g'), 80);
    nm := public.poll_name_norm(t);
    continue when nm = '';
    -- the same person already written (the most written one if several are near)
    k := (select z.k from (select v.option_id k, count(*) n from public.poll_votes v where v.poll_id = p.id and v.round = p.round group by v.option_id) z
           where public.poll_name_near(nm, public.poll_name_norm(substr(z.k, 3))) order by z.n desc, z.k limit 1);
    k := coalesce(k, (select x from unnest(ks) x where public.poll_name_near(nm, public.poll_name_norm(substr(x, 3))) limit 1), 'w:' || nm);
    if k = any(ks) then return 'dup'; end if;
    ks := ks || k; es := es || t;
  end loop;
  if coalesce(array_length(ks, 1), 0) = 0 then return 'bad'; end if;
  if array_length(ks, 1) > p.write_max then return 'limit'; end if;
  insert into public.poll_votes (poll_id, round, option_id, voter, entry) select p.id, p.round, ks[i], p_voter, es[i] from generate_subscripts(ks, 1) i;
  return 'ok';
end $$;
revoke all on function public.poll_write(text, text[], text, uuid) from public;
grant execute on function public.poll_write(text, text[], text, uuid) to anon, authenticated;

-- the name shown for a person: the spelling written most often, on a tie the first one written
create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  s := (select x from public.poll_sets x where x.results_token = p_token);
  if s.id is not null then
    perm := true;
    -- nominees / the winner chosen beforehand
    if s.display is not null then
      p := (select x from public.polls x where x.id = (s.display->>'poll')::uuid and x.set_id = s.id);
      if p.id is not null and s.display->>'mode' = 'splash' then
        return jsonb_build_object('state', 'splash', 'now', now(), 'poll', p.id, 'at', s.display->>'at', 'topic', nullif(p.topic, ''),
          'splash', p.brand, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all);
      end if;
      if p.id is not null then
        return jsonb_build_object('state', case when s.display->>'mode' = 'winner' then 'reveal' else 'nominees' end, 'now', now(),
          'poll', p.id, 'round', p.round, 'at', s.display->>'at', 'topic', nullif(p.topic, ''), 'question', p.question,
          'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          'options', case when p.kind = 'write' then
                        -- typed names: the most written one(s) win, shown only now
                        (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'winner', s.display->>'mode' = 'winner' and z.n = z.m) order by z.n desc, z.t), '[]'::jsonb) from (
                           select v.option_id k, count(*) n, max(count(*)) over () m,
                                  (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                                     group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                             from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                             group by v.option_id order by count(*) desc, v.option_id limit 15) z)
                      else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                        'winner', s.display->>'mode' = 'winner' and coalesce(o->>'winner', '') = 'true') order by n), '[]'::jsonb)
                      from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
      end if;
    end if;
    p := public.poll_set_current(s.id);
    if p.id is null then p := (select x from public.polls x where x.set_id = s.id and x.ends_at <= now() order by x.ends_at desc limit 1); end if;
  else
    p := (select x from public.polls x where x.results_token = p_token);
    if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  -- typed names on the voting's screen: when the time is up only "voting ended" – the winner waits for the editor's button
  if perm and p.kind = 'write' and public.poll_state(p) = 'ended' then
    return jsonb_build_object('state', 'ended', 'hold', true, 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
      'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', s.brand, 'multi', p.multi, 'write', true,
      'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token, 'total', 0, 'options', '[]'::jsonb);
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'vote_token', case when perm then s.vote_token end,
    'write', p.kind = 'write',
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', case when p.kind = 'write' then
                 -- names typed by the voters: the same name (letter case and spaces aside) counts together,
                 -- shown as it was typed most often; the 15 most written
                 (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'votes', z.n) order by z.n desc, z.t), '[]'::jsonb) from (
                    select v.option_id k, count(*) n,
                           (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                              group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                      from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                      group by v.option_id order by count(*) desc, v.option_id limit 15) z)
               else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
end $$;
grant execute on function public.poll_results(text) to anon, authenticated;



-- ============================================================
-- Balsavimai, 12 dalis (paleisti po polls11.sql): „PARODYTI NOMINACIJĄ“
--  * rezultatų ekrane – tik tema ir nominacija (be nominantų, be QR kodo),
--    bet kuriai nominacijai
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  s := (select x from public.poll_sets x where x.results_token = p_token);
  if s.id is not null then
    perm := true;
    -- nominees / the winner chosen beforehand
    if s.display is not null then
      p := (select x from public.polls x where x.id = (s.display->>'poll')::uuid and x.set_id = s.id);
      if p.id is not null and s.display->>'mode' = 'nomination' then
        return jsonb_build_object('state', 'nomination', 'now', now(), 'poll', p.id, 'round', p.round, 'at', s.display->>'at',
          'topic', nullif(p.topic, ''), 'question', p.question, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all);
      end if;
      if p.id is not null and s.display->>'mode' = 'splash' then
        return jsonb_build_object('state', 'splash', 'now', now(), 'poll', p.id, 'at', s.display->>'at', 'topic', nullif(p.topic, ''),
          'splash', p.brand, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all);
      end if;
      if p.id is not null then
        return jsonb_build_object('state', case when s.display->>'mode' = 'winner' then 'reveal' else 'nominees' end, 'now', now(),
          'poll', p.id, 'round', p.round, 'at', s.display->>'at', 'topic', nullif(p.topic, ''), 'question', p.question,
          'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          'options', case when p.kind = 'write' then
                        -- typed names: the most written one(s) win, shown only now
                        (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'winner', s.display->>'mode' = 'winner' and z.n = z.m) order by z.n desc, z.t), '[]'::jsonb) from (
                           select v.option_id k, count(*) n, max(count(*)) over () m,
                                  (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                                     group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                             from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                             group by v.option_id order by count(*) desc, v.option_id limit 15) z)
                      else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                        'winner', s.display->>'mode' = 'winner' and coalesce(o->>'winner', '') = 'true') order by n), '[]'::jsonb)
                      from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
      end if;
    end if;
    p := public.poll_set_current(s.id);
    if p.id is null then p := (select x from public.polls x where x.set_id = s.id and x.ends_at <= now() order by x.ends_at desc limit 1); end if;
  else
    p := (select x from public.polls x where x.results_token = p_token);
    if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  -- typed names on the voting's screen: when the time is up only "voting ended" – the winner waits for the editor's button
  if perm and p.kind = 'write' and public.poll_state(p) = 'ended' then
    return jsonb_build_object('state', 'ended', 'hold', true, 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
      'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', s.brand, 'multi', p.multi, 'write', true,
      'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token, 'total', 0, 'options', '[]'::jsonb);
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'vote_token', case when perm then s.vote_token end,
    'write', p.kind = 'write',
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', case when p.kind = 'write' then
                 -- names typed by the voters: the same name (letter case and spaces aside) counts together,
                 -- shown as it was typed most often; the 15 most written
                 (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'votes', z.n) order by z.n desc, z.t), '[]'::jsonb) from (
                    select v.option_id k, count(*) n,
                           (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                              group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                      from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                      group by v.option_id order by count(*) desc, v.option_id limit 15) z)
               else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
end $$;
grant execute on function public.poll_results(text) to anon, authenticated;

-- the editor (admin, or anyone with the editor link)
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; s public.poll_sets; v_id uuid; v_new uuid; v_set uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  -- votings
  if p_action = 'sets' then
    return coalesce((select jsonb_agg(to_jsonb(x) || jsonb_build_object(
              'questions', (select count(*) from public.polls q where q.set_id = x.id and q.kind <> 'splash'),
              'live', (select count(*) from public.polls q where q.set_id = x.id and q.ends_at > now()))
            order by x.created_at desc) from public.poll_sets x), '[]'::jsonb);
  elsif p_action = 'set_create' then
    v_new := gen_random_uuid();
    insert into public.poll_sets (id, name) values (v_new, left(coalesce(nullif(trim(a->>'name'), ''), 'Balsavimas'), 200));
    return (select to_jsonb(x) from public.poll_sets x where x.id = v_new);
  elsif p_action = 'set_update' then
    update public.poll_sets set
        name = left(coalesce(nullif(trim(a->>'name'), ''), name), 200), brand = coalesce(a->'brand', brand),
        results_w = greatest(100, least(8000, coalesce((a->>'results_w')::int, results_w))),
        results_h = greatest(100, least(8000, coalesce((a->>'results_h')::int, results_h))),
        show_all = coalesce((a->>'show_all')::boolean, show_all), updated_at = now()
      where id = (a->>'id')::uuid;
    s := (select x from public.poll_sets x where x.id = (a->>'id')::uuid);
    if s.id is null then raise exception 'Balsavimas nerastas'; end if;
    return to_jsonb(s);
  elsif p_action = 'set_get' then
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'id')::uuid);
  elsif p_action = 'hide' then
    update public.poll_sets set display = null, updated_at = now() where id = (a->>'set')::uuid;
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'set')::uuid);
  elsif p_action = 'set_delete' then
    delete from public.poll_sets where id = (a->>'id')::uuid;
    return '{}'::jsonb;
  -- questions of one voting
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x where x.set_id = (a->>'set')::uuid), '[]'::jsonb);
  elsif p_action = 'create' then
    v_set := (a->>'set')::uuid;
    if not exists (select 1 from public.poll_sets where id = v_set) then raise exception 'Balsavimas nerastas'; end if;
    v_new := gen_random_uuid();
    insert into public.polls (id, set_id, kind, brand, topic, question, options, duration_sec, multi, sort, created_by)
      values (v_new, v_set, case when a->>'kind' in ('splash', 'write') then a->>'kind' else 'question' end, coalesce(a->'brand', '{}'::jsonb),
              left(coalesce(a->>'topic', ''), 200), left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb),
              coalesce((a->>'duration_sec')::int, 60), coalesce((a->>'multi')::boolean, false),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls where set_id = v_set)), auth.uid());
    update public.polls set write_max = greatest(1, least(50, coalesce((a->>'write_max')::int, 1))) where id = v_new;
    return (select to_jsonb(x) from public.polls x where x.id = v_new);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    v_new := gen_random_uuid();
    insert into public.poll_assets (id, mime, data, bytes) values (v_new, a->>'mime', a->>'data', length(a->>'data') * 3 / 4);
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        topic = left(coalesce(a->>'topic', topic), 200), question = left(coalesce(a->>'question', question), 500),
        options = coalesce(a->'options', options), duration_sec = coalesce((a->>'duration_sec')::int, duration_sec),
        multi = coalesce((a->>'multi')::boolean, multi), sort = coalesce((a->>'sort')::int, sort),
        brand = case when kind = 'splash' then coalesce(a->'brand', brand) else brand end,
        kind = case when kind <> 'splash' and a->>'kind' in ('question', 'write') then a->>'kind' else kind end,
        write_max = greatest(1, least(50, coalesce((a->>'write_max')::int, write_max))), updated_at = now()
      where id = v_id;
    p := (select x from public.polls x where x.id = v_id);
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    if exists (select 1 from public.polls q where q.id = v_id and q.kind = 'splash') then raise exception 'Užsklanda nėra balsavimas'; end if;
    update public.poll_sets set display = null where id = (select q.set_id from public.polls q where q.id = v_id);
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'show' then
    -- the results screen shows this question's nominees, or its winner chosen beforehand (no voting)
    p := (select x from public.polls x where x.id = v_id);
    if p.id is null then raise exception 'Klausimas nerastas'; end if;
    if (a->>'mode' = 'splash') <> (p.kind = 'splash') then raise exception 'Netinkamas rodymas'; end if;
    if a->>'mode' = 'winner' and p.kind = 'write' and not exists (select 1 from public.poll_votes v where v.poll_id = p.id and v.round = p.round) then
      raise exception 'Dar niekas neįrašė vardo'; end if;
    if a->>'mode' = 'winner' and p.kind <> 'write' and not exists (select 1 from jsonb_array_elements(p.options) o where o->>'winner' = 'true') then
      raise exception 'Nugalėtojas nepažymėtas'; end if;
    update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
      where set_id = p.set_id and ends_at > now();
    update public.poll_sets set display = jsonb_build_object('mode', case when a->>'mode' in ('winner', 'splash', 'nomination') then a->>'mode' else 'nominees' end, 'poll', p.id, 'at', now()),
        updated_at = now()
      where id = p.set_id;
    return (select to_jsonb(x) from public.poll_sets x where x.id = p.set_id);
  elsif p_action = 'stop' then
    p := public.poll_do_stop(v_id);
  else
    raise exception 'Nežinomas veiksmas';
  end if;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return to_jsonb(p);
end $$;
revoke all on function public.poll_admin(text, text, jsonb) from public;
grant execute on function public.poll_admin(text, text, jsonb) to anon, authenticated;


-- ============================================================
-- Balsavimai, 13 dalis (paleisti po polls12.sql): „Parodyti nominaciją“
-- rezultatų ekrane rodo ir balsavimo QR kodą.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  s := (select x from public.poll_sets x where x.results_token = p_token);
  if s.id is not null then
    perm := true;
    -- nominees / the winner chosen beforehand
    if s.display is not null then
      p := (select x from public.polls x where x.id = (s.display->>'poll')::uuid and x.set_id = s.id);
      if p.id is not null and s.display->>'mode' = 'nomination' then
        return jsonb_build_object('state', 'nomination', 'now', now(), 'poll', p.id, 'round', p.round, 'at', s.display->>'at',
          'topic', nullif(p.topic, ''), 'question', p.question, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          'vote_token', s.vote_token);
      end if;
      if p.id is not null and s.display->>'mode' = 'splash' then
        return jsonb_build_object('state', 'splash', 'now', now(), 'poll', p.id, 'at', s.display->>'at', 'topic', nullif(p.topic, ''),
          'splash', p.brand, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all);
      end if;
      if p.id is not null then
        return jsonb_build_object('state', case when s.display->>'mode' = 'winner' then 'reveal' else 'nominees' end, 'now', now(),
          'poll', p.id, 'round', p.round, 'at', s.display->>'at', 'topic', nullif(p.topic, ''), 'question', p.question,
          'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          'options', case when p.kind = 'write' then
                        -- typed names: the most written one(s) win, shown only now
                        (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'winner', s.display->>'mode' = 'winner' and z.n = z.m) order by z.n desc, z.t), '[]'::jsonb) from (
                           select v.option_id k, count(*) n, max(count(*)) over () m,
                                  (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                                     group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                             from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                             group by v.option_id order by count(*) desc, v.option_id limit 15) z)
                      else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                        'winner', s.display->>'mode' = 'winner' and coalesce(o->>'winner', '') = 'true') order by n), '[]'::jsonb)
                      from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
      end if;
    end if;
    p := public.poll_set_current(s.id);
    if p.id is null then p := (select x from public.polls x where x.set_id = s.id and x.ends_at <= now() order by x.ends_at desc limit 1); end if;
  else
    p := (select x from public.polls x where x.results_token = p_token);
    if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  -- typed names on the voting's screen: when the time is up only "voting ended" – the winner waits for the editor's button
  if perm and p.kind = 'write' and public.poll_state(p) = 'ended' then
    return jsonb_build_object('state', 'ended', 'hold', true, 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
      'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', s.brand, 'multi', p.multi, 'write', true,
      'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token, 'total', 0, 'options', '[]'::jsonb);
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'vote_token', case when perm then s.vote_token end,
    'write', p.kind = 'write',
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', case when p.kind = 'write' then
                 -- names typed by the voters: the same name (letter case and spaces aside) counts together,
                 -- shown as it was typed most often; the 15 most written
                 (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'votes', z.n) order by z.n desc, z.t), '[]'::jsonb) from (
                    select v.option_id k, count(*) n,
                           (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                              group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                      from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                      group by v.option_id order by count(*) desc, v.option_id limit 15) z)
               else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
end $$;
grant execute on function public.poll_results(text) to anon, authenticated;


-- ============================================================
-- Balsavimai, 14 dalis (paleisti po polls13.sql): VISOMS NOMINACIJOMS
--  * pasibaigus laikui rezultatų ekranas rodo „Balsavimas baigėsi“
--    (laimėtojas nesiunčiamas, kol nepaspaustas mygtukas)
--  * „Parodyti laimėtoją“: daugiausiai balsų surinkęs nominantas
--    (lygiųjų atveju – visi); jei balsų nėra – iš anksto pažymėtas 🏆
--  * „Parodyti nominaciją“ be QR kodo, kai laimėtojas pažymėtas iš anksto
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  s := (select x from public.poll_sets x where x.results_token = p_token);
  if s.id is not null then
    perm := true;
    -- nominees / the winner chosen beforehand
    if s.display is not null then
      p := (select x from public.polls x where x.id = (s.display->>'poll')::uuid and x.set_id = s.id);
      if p.id is not null and s.display->>'mode' = 'nomination' then
        return jsonb_build_object('state', 'nomination', 'now', now(), 'poll', p.id, 'round', p.round, 'at', s.display->>'at',
          'topic', nullif(p.topic, ''), 'question', p.question, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          -- a winner marked 🏆 beforehand means no voting: then no QR code
          'vote_token', case when not exists (select 1 from jsonb_array_elements(p.options) o where o->>'winner' = 'true') then s.vote_token end);
      end if;
      if p.id is not null and s.display->>'mode' = 'splash' then
        return jsonb_build_object('state', 'splash', 'now', now(), 'poll', p.id, 'at', s.display->>'at', 'topic', nullif(p.topic, ''),
          'splash', p.brand, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all);
      end if;
      if p.id is not null then
        return jsonb_build_object('state', case when s.display->>'mode' = 'winner' then 'reveal' else 'nominees' end, 'now', now(),
          'poll', p.id, 'round', p.round, 'at', s.display->>'at', 'topic', nullif(p.topic, ''), 'question', p.question,
          'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          'options', case when p.kind = 'write' then
                        -- typed names: the most written one(s) win, shown only now
                        (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'winner', s.display->>'mode' = 'winner' and z.n = z.m) order by z.n desc, z.t), '[]'::jsonb) from (
                           select v.option_id k, count(*) n, max(count(*)) over () m,
                                  (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                                     group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                             from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                             group by v.option_id order by count(*) desc, v.option_id limit 15) z)
                      -- nominees: the most voted one(s) win; with no votes – the one marked 🏆 beforehand
                      else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                        'winner', s.display->>'mode' = 'winner' and case when vm.m > 0 then vc.cnt = vm.m else coalesce(o->>'winner', '') = 'true' end) order by x.n), '[]'::jsonb)
                      from jsonb_array_elements(p.options) with ordinality as x(o, n)
                      cross join lateral (select count(*) cnt from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = x.o->>'id') vc
                      cross join (select coalesce(max(q.c), 0) m from (select count(*) c from public.poll_votes v where v.poll_id = p.id and v.round = p.round group by v.option_id) q) vm) end);
      end if;
    end if;
    p := public.poll_set_current(s.id);
    if p.id is null then p := (select x from public.polls x where x.set_id = s.id and x.ends_at <= now() order by x.ends_at desc limit 1); end if;
  else
    p := (select x from public.polls x where x.results_token = p_token);
    if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  -- on the voting's screen: when the time is up only "voting ended" – the winner waits for the editor's button
  if perm and public.poll_state(p) = 'ended' then
    return jsonb_build_object('state', 'ended', 'hold', true, 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
      'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', s.brand, 'multi', p.multi, 'write', p.kind = 'write',
      'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token, 'total', 0, 'options', '[]'::jsonb);
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'vote_token', case when perm then s.vote_token end,
    'write', p.kind = 'write',
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', case when p.kind = 'write' then
                 -- names typed by the voters: the same name (letter case and spaces aside) counts together,
                 -- shown as it was typed most often; the 15 most written
                 (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'votes', z.n) order by z.n desc, z.t), '[]'::jsonb) from (
                    select v.option_id k, count(*) n,
                           (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                              group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                      from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                      group by v.option_id order by count(*) desc, v.option_id limit 15) z)
               else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
end $$;
grant execute on function public.poll_results(text) to anon, authenticated;

-- the editor (admin, or anyone with the editor link)
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; s public.poll_sets; v_id uuid; v_new uuid; v_set uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  -- votings
  if p_action = 'sets' then
    return coalesce((select jsonb_agg(to_jsonb(x) || jsonb_build_object(
              'questions', (select count(*) from public.polls q where q.set_id = x.id and q.kind <> 'splash'),
              'live', (select count(*) from public.polls q where q.set_id = x.id and q.ends_at > now()))
            order by x.created_at desc) from public.poll_sets x), '[]'::jsonb);
  elsif p_action = 'set_create' then
    v_new := gen_random_uuid();
    insert into public.poll_sets (id, name) values (v_new, left(coalesce(nullif(trim(a->>'name'), ''), 'Balsavimas'), 200));
    return (select to_jsonb(x) from public.poll_sets x where x.id = v_new);
  elsif p_action = 'set_update' then
    update public.poll_sets set
        name = left(coalesce(nullif(trim(a->>'name'), ''), name), 200), brand = coalesce(a->'brand', brand),
        results_w = greatest(100, least(8000, coalesce((a->>'results_w')::int, results_w))),
        results_h = greatest(100, least(8000, coalesce((a->>'results_h')::int, results_h))),
        show_all = coalesce((a->>'show_all')::boolean, show_all), updated_at = now()
      where id = (a->>'id')::uuid;
    s := (select x from public.poll_sets x where x.id = (a->>'id')::uuid);
    if s.id is null then raise exception 'Balsavimas nerastas'; end if;
    return to_jsonb(s);
  elsif p_action = 'set_get' then
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'id')::uuid);
  elsif p_action = 'hide' then
    update public.poll_sets set display = null, updated_at = now() where id = (a->>'set')::uuid;
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'set')::uuid);
  elsif p_action = 'set_delete' then
    delete from public.poll_sets where id = (a->>'id')::uuid;
    return '{}'::jsonb;
  -- questions of one voting
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x where x.set_id = (a->>'set')::uuid), '[]'::jsonb);
  elsif p_action = 'create' then
    v_set := (a->>'set')::uuid;
    if not exists (select 1 from public.poll_sets where id = v_set) then raise exception 'Balsavimas nerastas'; end if;
    v_new := gen_random_uuid();
    insert into public.polls (id, set_id, kind, brand, topic, question, options, duration_sec, multi, sort, created_by)
      values (v_new, v_set, case when a->>'kind' in ('splash', 'write') then a->>'kind' else 'question' end, coalesce(a->'brand', '{}'::jsonb),
              left(coalesce(a->>'topic', ''), 200), left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb),
              coalesce((a->>'duration_sec')::int, 60), coalesce((a->>'multi')::boolean, false),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls where set_id = v_set)), auth.uid());
    update public.polls set write_max = greatest(1, least(50, coalesce((a->>'write_max')::int, 1))) where id = v_new;
    return (select to_jsonb(x) from public.polls x where x.id = v_new);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    v_new := gen_random_uuid();
    insert into public.poll_assets (id, mime, data, bytes) values (v_new, a->>'mime', a->>'data', length(a->>'data') * 3 / 4);
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        topic = left(coalesce(a->>'topic', topic), 200), question = left(coalesce(a->>'question', question), 500),
        options = coalesce(a->'options', options), duration_sec = coalesce((a->>'duration_sec')::int, duration_sec),
        multi = coalesce((a->>'multi')::boolean, multi), sort = coalesce((a->>'sort')::int, sort),
        brand = case when kind = 'splash' then coalesce(a->'brand', brand) else brand end,
        kind = case when kind <> 'splash' and a->>'kind' in ('question', 'write') then a->>'kind' else kind end,
        write_max = greatest(1, least(50, coalesce((a->>'write_max')::int, write_max))), updated_at = now()
      where id = v_id;
    p := (select x from public.polls x where x.id = v_id);
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    if exists (select 1 from public.polls q where q.id = v_id and q.kind = 'splash') then raise exception 'Užsklanda nėra balsavimas'; end if;
    update public.poll_sets set display = null where id = (select q.set_id from public.polls q where q.id = v_id);
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'show' then
    -- the results screen shows this question's nominees, or its winner chosen beforehand (no voting)
    p := (select x from public.polls x where x.id = v_id);
    if p.id is null then raise exception 'Klausimas nerastas'; end if;
    if (a->>'mode' = 'splash') <> (p.kind = 'splash') then raise exception 'Netinkamas rodymas'; end if;
    if a->>'mode' = 'winner' and p.kind = 'write' and not exists (select 1 from public.poll_votes v where v.poll_id = p.id and v.round = p.round) then
      raise exception 'Dar niekas neįrašė vardo'; end if;
    if a->>'mode' = 'winner' and p.kind <> 'write' and not exists (select 1 from public.poll_votes v where v.poll_id = p.id and v.round = p.round) and not exists (select 1 from jsonb_array_elements(p.options) o where o->>'winner' = 'true') then
      raise exception 'Nugalėtojas nepažymėtas'; end if;
    update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
      where set_id = p.set_id and ends_at > now();
    update public.poll_sets set display = jsonb_build_object('mode', case when a->>'mode' in ('winner', 'splash', 'nomination') then a->>'mode' else 'nominees' end, 'poll', p.id, 'at', now()),
        updated_at = now()
      where id = p.set_id;
    return (select to_jsonb(x) from public.poll_sets x where x.id = p.set_id);
  elsif p_action = 'stop' then
    p := public.poll_do_stop(v_id);
  else
    raise exception 'Nežinomas veiksmas';
  end if;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return to_jsonb(p);
end $$;
revoke all on function public.poll_admin(text, text, jsonb) from public;
grant execute on function public.poll_admin(text, text, jsonb) to anon, authenticated;


-- ============================================================
-- Balsavimai, 15 dalis (paleisti po polls14.sql): KELIOS TEMOS – ĮRAŠO PATYS
--  * nominacijos tipas „Kelios temos“ (polls.kind = 'multi'): telefone
--    visos temos, kiekvienai įrašomas vardas ir pavardė (tas pats vardas
--    gali būti keliose temose); balsuoti – tik užpildžius visas temas
--  * pasibaigus laikui – „Balsavimas baigėsi“; kiekvienos temos laimėtojas
--    (daugiausiai kartų įrašytas vardas) rodomas atskiru mygtuku
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.poll_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; st text; s public.poll_sets;
begin
  s := (select x from public.poll_sets x where x.vote_token = p_token);
  if s.id is not null then p := public.poll_set_current(s.id);
  else p := (select x from public.polls x where x.vote_token = p_token);
       if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if; end if;
  if p.id is null then return jsonb_build_object('state', case when s.id is not null then 'idle' else 'invalid' end, 'now', now(), 'brand', coalesce(s.brand, '{}'::jsonb)); end if;
  st := public.poll_state(p);
  if s.id is not null and p_token = s.vote_token and st not in ('waiting', 'live') then st := 'idle'; end if;
  return jsonb_build_object('state', st, 'now', now(), 'poll', p.id, 'round', p.round, 'starts_at', p.starts_at, 'ends_at', p.ends_at,
    'brand', coalesce(s.brand, p.brand), 'multi', p.multi, 'write', p.kind = 'write', 'write_max', p.write_max, 'mw', p.kind = 'multi',
    'topic', case when st in ('waiting', 'live') then nullif(p.topic, '') end,
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' and p.kind <> 'write' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;
grant execute on function public.poll_public(text) to anon, authenticated;

create or replace function public.poll_vote_many(p_token text, p_options text[], p_voter text, p_poll uuid) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; opts text[];
begin
  s := (select x from public.poll_sets x where x.vote_token = p_token);
  if s.id is not null then p := (select x from public.polls x where x.id = p_poll and x.set_id = s.id);
  else p := (select x from public.polls x where x.vote_token = p_token); end if;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if coalesce(length(p_voter), 0) not between 8 and 100 or p.kind <> 'question' then return 'bad'; end if;
  opts := (select array_agg(distinct o) from unnest(coalesce(p_options, '{}'::text[])) o);
  if coalesce(array_length(opts, 1), 0) = 0 or (not p.multi and array_length(opts, 1) > 1) then return 'bad'; end if;
  if exists (select 1 from unnest(opts) x where not exists (select 1 from jsonb_array_elements(p.options) o where o->>'id' = x)) then return 'bad'; end if;
  perform pg_advisory_xact_lock(hashtext(p.id::text || ':' || p_voter));
  if exists (select 1 from public.poll_votes where poll_id = p.id and round = p.round and voter = p_voter) then return 'already'; end if;
  insert into public.poll_votes (poll_id, round, option_id, voter) select p.id, p.round, x, p_voter from unnest(opts) x;
  return 'ok';
end $$;
revoke all on function public.poll_vote_many(text, text[], text, uuid) from public;
grant execute on function public.poll_vote_many(text, text[], text, uuid) to anon, authenticated;

-- several topics: one name per topic, all topics filled, one submission per phone; the same name may be in
-- different topics; within a topic a name near one already written counts for it
create or replace function public.poll_mwrite(p_token text, p_topics text[], p_names text[], p_voter text, p_poll uuid) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; i int; tid text; t text; nm text; k text; ks text[] := '{}'; es text[] := '{}'; tn int;
begin
  s := (select x from public.poll_sets x where x.vote_token = p_token);
  if s.id is not null then p := (select x from public.polls x where x.id = p_poll and x.set_id = s.id);
  else p := (select x from public.polls x where x.vote_token = p_token); end if;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if p.kind <> 'multi' or coalesce(length(p_voter), 0) not between 8 and 100 then return 'bad'; end if;
  tn := jsonb_array_length(p.options);
  if tn = 0 or coalesce(array_length(p_topics, 1), 0) <> tn or coalesce(array_length(p_names, 1), 0) <> tn then return 'bad'; end if;
  if (select count(distinct x) from unnest(p_topics) x where exists (select 1 from jsonb_array_elements(p.options) o where o->>'id' = x)) <> tn then return 'bad'; end if;
  perform pg_advisory_xact_lock(hashtext('poll_write:' || p.id::text));
  if exists (select 1 from public.poll_votes where poll_id = p.id and round = p.round and voter = p_voter) then return 'already'; end if;
  for i in 1..tn loop
    tid := p_topics[i];
    t := left(regexp_replace(btrim(coalesce(p_names[i], '')), '\s+', ' ', 'g'), 80);
    nm := public.poll_name_norm(t);
    if nm = '' then return 'bad'; end if;
    k := (select z.k from (select v.option_id k, count(*) c from public.poll_votes v
                             where v.poll_id = p.id and v.round = p.round and v.option_id like tid || ':%' group by v.option_id) z
           where public.poll_name_near(nm, public.poll_name_norm(substr(z.k, length(tid) + 4))) order by z.c desc, z.k limit 1);
    ks := ks || coalesce(k, tid || ':w:' || nm); es := es || t;
  end loop;
  insert into public.poll_votes (poll_id, round, option_id, voter, entry) select p.id, p.round, ks[j], p_voter, es[j] from generate_subscripts(ks, 1) j;
  return 'ok';
end $$;
revoke all on function public.poll_mwrite(text, text[], text[], text, uuid) from public;
grant execute on function public.poll_mwrite(text, text[], text[], text, uuid) to anon, authenticated;

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  s := (select x from public.poll_sets x where x.results_token = p_token);
  if s.id is not null then
    perm := true;
    -- nominees / the winner chosen beforehand
    if s.display is not null then
      p := (select x from public.polls x where x.id = (s.display->>'poll')::uuid and x.set_id = s.id);
      if p.id is not null and s.display->>'mode' = 'nomination' then
        return jsonb_build_object('state', 'nomination', 'now', now(), 'poll', p.id, 'round', p.round, 'at', s.display->>'at',
          'topic', nullif(p.topic, ''), 'question', p.question, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          -- a winner marked 🏆 beforehand means no voting: then no QR code
          'vote_token', case when not exists (select 1 from jsonb_array_elements(p.options) o where o->>'winner' = 'true') then s.vote_token end);
      end if;
      if p.id is not null and s.display->>'mode' = 'splash' then
        return jsonb_build_object('state', 'splash', 'now', now(), 'poll', p.id, 'at', s.display->>'at', 'topic', nullif(p.topic, ''),
          'splash', p.brand, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all);
      end if;
      if p.id is not null then
        return jsonb_build_object('state', case when s.display->>'mode' = 'winner' then 'reveal' else 'nominees' end, 'now', now(),
          'poll', p.id, 'round', p.round, 'at', s.display->>'at', 'topic', nullif(p.topic, ''), 'question', p.question,
          'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          'options', case when p.kind = 'multi' then
                        -- several topics: each topic (or only the one chosen) with its most written name(s)
                        (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text', 'winner', s.display->>'mode' = 'winner',
                           'names', case when s.display->>'mode' = 'winner' then (select coalesce(jsonb_agg(z.t order by z.t), '[]'::jsonb) from (
                              select count(*) c, max(count(*)) over () m, (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                                from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id like (o->>'id') || ':%' group by v.option_id) z where z.c = z.m)
                             else '[]'::jsonb end) order by x.n), '[]'::jsonb)
                         from jsonb_array_elements(p.options) with ordinality as x(o, n)
                         where coalesce(s.display->>'topic', '') = '' or o->>'id' = s.display->>'topic')
                      when p.kind = 'write' then
                        -- typed names: the most written one(s) win, shown only now
                        (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'winner', s.display->>'mode' = 'winner' and z.n = z.m) order by z.n desc, z.t), '[]'::jsonb) from (
                           select v.option_id k, count(*) n, max(count(*)) over () m,
                                  (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                                     group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                             from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                             group by v.option_id order by count(*) desc, v.option_id limit 15) z)
                      -- nominees: the most voted one(s) win; with no votes – the one marked 🏆 beforehand
                      else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                        'winner', s.display->>'mode' = 'winner' and case when vm.m > 0 then vc.cnt = vm.m else coalesce(o->>'winner', '') = 'true' end) order by x.n), '[]'::jsonb)
                      from jsonb_array_elements(p.options) with ordinality as x(o, n)
                      cross join lateral (select count(*) cnt from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = x.o->>'id') vc
                      cross join (select coalesce(max(q.c), 0) m from (select count(*) c from public.poll_votes v where v.poll_id = p.id and v.round = p.round group by v.option_id) q) vm) end);
      end if;
    end if;
    p := public.poll_set_current(s.id);
    if p.id is null then p := (select x from public.polls x where x.set_id = s.id and x.ends_at <= now() order by x.ends_at desc limit 1); end if;
  else
    p := (select x from public.polls x where x.results_token = p_token);
    if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  -- on the voting's screen: when the time is up only "voting ended" – the winner waits for the editor's button
  if perm and public.poll_state(p) = 'ended' then
    return jsonb_build_object('state', 'ended', 'hold', true, 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
      'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', s.brand, 'multi', p.multi, 'write', p.kind = 'write', 'mw', p.kind = 'multi',
      'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token, 'total', 0, 'options', '[]'::jsonb);
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'vote_token', case when perm then s.vote_token end,
    'write', p.kind = 'write',
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'mw', p.kind = 'multi',
    'options', case when p.kind = 'multi' then
                 -- several topics: per topic the entries and the 5 most written names
                 (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                    'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id like (o->>'id') || ':%'),
                    'top', (select coalesce(jsonb_agg(jsonb_build_object('text', z.t, 'votes', z.c) order by z.c desc, z.t), '[]'::jsonb) from (
                       select count(*) c, (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                         from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id like (o->>'id') || ':%'
                         group by v.option_id order by count(*) desc, v.option_id limit 5) z)) order by x.n), '[]'::jsonb)
                  from jsonb_array_elements(p.options) with ordinality as x(o, n))
               when p.kind = 'write' then
                 -- names typed by the voters: the same name (letter case and spaces aside) counts together,
                 -- shown as it was typed most often; the 15 most written
                 (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'votes', z.n) order by z.n desc, z.t), '[]'::jsonb) from (
                    select v.option_id k, count(*) n,
                           (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                              group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                      from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                      group by v.option_id order by count(*) desc, v.option_id limit 15) z)
               else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
end $$;
grant execute on function public.poll_results(text) to anon, authenticated;

-- the editor (admin, or anyone with the editor link)
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; s public.poll_sets; v_id uuid; v_new uuid; v_set uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  -- votings
  if p_action = 'sets' then
    return coalesce((select jsonb_agg(to_jsonb(x) || jsonb_build_object(
              'questions', (select count(*) from public.polls q where q.set_id = x.id and q.kind <> 'splash'),
              'live', (select count(*) from public.polls q where q.set_id = x.id and q.ends_at > now()))
            order by x.created_at desc) from public.poll_sets x), '[]'::jsonb);
  elsif p_action = 'set_create' then
    v_new := gen_random_uuid();
    insert into public.poll_sets (id, name) values (v_new, left(coalesce(nullif(trim(a->>'name'), ''), 'Balsavimas'), 200));
    return (select to_jsonb(x) from public.poll_sets x where x.id = v_new);
  elsif p_action = 'set_update' then
    update public.poll_sets set
        name = left(coalesce(nullif(trim(a->>'name'), ''), name), 200), brand = coalesce(a->'brand', brand),
        results_w = greatest(100, least(8000, coalesce((a->>'results_w')::int, results_w))),
        results_h = greatest(100, least(8000, coalesce((a->>'results_h')::int, results_h))),
        show_all = coalesce((a->>'show_all')::boolean, show_all), updated_at = now()
      where id = (a->>'id')::uuid;
    s := (select x from public.poll_sets x where x.id = (a->>'id')::uuid);
    if s.id is null then raise exception 'Balsavimas nerastas'; end if;
    return to_jsonb(s);
  elsif p_action = 'set_get' then
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'id')::uuid);
  elsif p_action = 'hide' then
    update public.poll_sets set display = null, updated_at = now() where id = (a->>'set')::uuid;
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'set')::uuid);
  elsif p_action = 'set_delete' then
    delete from public.poll_sets where id = (a->>'id')::uuid;
    return '{}'::jsonb;
  -- questions of one voting
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x where x.set_id = (a->>'set')::uuid), '[]'::jsonb);
  elsif p_action = 'create' then
    v_set := (a->>'set')::uuid;
    if not exists (select 1 from public.poll_sets where id = v_set) then raise exception 'Balsavimas nerastas'; end if;
    v_new := gen_random_uuid();
    insert into public.polls (id, set_id, kind, brand, topic, question, options, duration_sec, multi, sort, created_by)
      values (v_new, v_set, case when a->>'kind' in ('splash', 'write', 'multi') then a->>'kind' else 'question' end, coalesce(a->'brand', '{}'::jsonb),
              left(coalesce(a->>'topic', ''), 200), left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb),
              coalesce((a->>'duration_sec')::int, 60), coalesce((a->>'multi')::boolean, false),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls where set_id = v_set)), auth.uid());
    update public.polls set write_max = greatest(1, least(50, coalesce((a->>'write_max')::int, 1))) where id = v_new;
    return (select to_jsonb(x) from public.polls x where x.id = v_new);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    v_new := gen_random_uuid();
    insert into public.poll_assets (id, mime, data, bytes) values (v_new, a->>'mime', a->>'data', length(a->>'data') * 3 / 4);
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        topic = left(coalesce(a->>'topic', topic), 200), question = left(coalesce(a->>'question', question), 500),
        options = coalesce(a->'options', options), duration_sec = coalesce((a->>'duration_sec')::int, duration_sec),
        multi = coalesce((a->>'multi')::boolean, multi), sort = coalesce((a->>'sort')::int, sort),
        brand = case when kind = 'splash' then coalesce(a->'brand', brand) else brand end,
        kind = case when kind <> 'splash' and a->>'kind' in ('question', 'write', 'multi') then a->>'kind' else kind end,
        write_max = greatest(1, least(50, coalesce((a->>'write_max')::int, write_max))), updated_at = now()
      where id = v_id;
    p := (select x from public.polls x where x.id = v_id);
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    if exists (select 1 from public.polls q where q.id = v_id and q.kind = 'splash') then raise exception 'Užsklanda nėra balsavimas'; end if;
    update public.poll_sets set display = null where id = (select q.set_id from public.polls q where q.id = v_id);
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'show' then
    -- the results screen shows this question's nominees, or its winner chosen beforehand (no voting)
    p := (select x from public.polls x where x.id = v_id);
    if p.id is null then raise exception 'Klausimas nerastas'; end if;
    if (a->>'mode' = 'splash') <> (p.kind = 'splash') then raise exception 'Netinkamas rodymas'; end if;
    if a->>'mode' = 'winner' and p.kind in ('write', 'multi') and not exists (select 1 from public.poll_votes v where v.poll_id = p.id and v.round = p.round) then
      raise exception 'Dar niekas neįrašė vardo'; end if;
    if a->>'mode' = 'winner' and p.kind not in ('write', 'multi') and not exists (select 1 from public.poll_votes v where v.poll_id = p.id and v.round = p.round) and not exists (select 1 from jsonb_array_elements(p.options) o where o->>'winner' = 'true') then
      raise exception 'Nugalėtojas nepažymėtas'; end if;
    update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
      where set_id = p.set_id and ends_at > now();
    update public.poll_sets set display = jsonb_build_object('mode', case when a->>'mode' in ('winner', 'splash', 'nomination') then a->>'mode' else 'nominees' end, 'poll', p.id, 'at', now(),
          'topic', case when p.kind = 'multi' and coalesce(a->>'topic', '') <> '' then a->>'topic' end),
        updated_at = now()
      where id = p.set_id;
    return (select to_jsonb(x) from public.poll_sets x where x.id = p.set_id);
  elsif p_action = 'stop' then
    p := public.poll_do_stop(v_id);
  else
    raise exception 'Nežinomas veiksmas';
  end if;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return to_jsonb(p);
end $$;
revoke all on function public.poll_admin(text, text, jsonb) from public;
grant execute on function public.poll_admin(text, text, jsonb) to anon, authenticated;


-- ============================================================
-- Balsavimai, 16 dalis – PATAISYMAS: „Nepavyko išsiųsti“ balsuojant
-- nominacijoje su keliomis temomis (ir su įrašomais vardais).
--  * sudeda viską, ko reikia vardų įrašymui (stulpeliai, panašių vardų
--    atpažinimas iš polls11.sql, poll_mwrite) – nesvarbu, kurie ankstesni
--    failai buvo paleisti
--  * liepia Supabase iš naujo nuskaityti funkcijų sąrašą
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

alter table public.polls add column if not exists kind text not null default 'question';
alter table public.polls add column if not exists write_max int not null default 1;
alter table public.poll_votes add column if not exists entry text;

-- letters only, without Lithuanian (and other) accents: „Vardėnis  VARDAS“ → „vardenis vardas“
create or replace function public.poll_name_norm(t text) returns text language sql immutable as $$
  select btrim(regexp_replace(regexp_replace(translate(lower(coalesce(t, '')), 'ąčęėįšųūžáàäâãåçéèêëíìîïñóòöôõúùûüýÿłńśźż', 'aceeisuuzaaaaaaceeeeiiiinooooouuuuyylnszz'), '[^a-z0-9 ]', ' ', 'g'), '\s+', ' ', 'g'))
$$;

-- edit distance: letters to add, remove or change; two neighbouring letters swapped count as one
create or replace function public.poll_lev(a text, b text) returns int language plpgsql immutable as $$
declare la int := length(a); lb int := length(b); pp int[]; prev int[]; cur int[]; i int; j int; c int; v int;
begin
  if a = b then return 0; end if;
  if la = 0 then return lb; end if;
  if lb = 0 then return la; end if;
  prev := array(select generate_series(0, lb));
  for i in 1..la loop
    cur := array[i];
    for j in 1..lb loop
      c := case when substr(a, i, 1) = substr(b, j, 1) then 0 else 1 end;
      v := least(prev[j + 1] + 1, cur[j] + 1, prev[j] + c);
      if i > 1 and j > 1 and substr(a, i, 1) = substr(b, j - 1, 1) and substr(a, i - 1, 1) = substr(b, j, 1) then v := least(v, pp[j - 1] + 1); end if;
      cur := cur || v;
    end loop;
    pp := prev; prev := cur;
  end loop;
  return prev[lb + 1];
end $$;

-- two words are the same name word: equal, or a small typo with the same first letter
create or replace function public.poll_word_near(x text, y text) returns boolean language sql immutable as $$
  select x = y or (left(x, 1) = left(y, 1) and greatest(length(x), length(y)) > 4
    and public.poll_lev(x, y) <= case when greatest(length(x), length(y)) <= 8 then 1 else 2 end)
$$;

-- two names (already normalized) are the same person: the same number of words, each near – in order or swapped
create or replace function public.poll_name_near(a text, b text) returns boolean language plpgsql immutable as $$
declare wa text[] := string_to_array(a, ' '); wb text[] := string_to_array(b, ' '); sa text[]; sb text[]; i int; ok boolean;
begin
  if a = b then return true; end if;
  if coalesce(array_length(wa, 1), 0) = 0 or coalesce(array_length(wa, 1), 0) <> coalesce(array_length(wb, 1), 0) then return false; end if;
  ok := true;
  for i in 1..array_length(wa, 1) loop
    if not public.poll_word_near(wa[i], wb[i]) then ok := false; exit; end if;
  end loop;
  if ok then return true; end if;
  sa := array(select w from unnest(wa) w order by w);
  sb := array(select w from unnest(wb) w order by w);
  for i in 1..array_length(sa, 1) loop
    if not public.poll_word_near(sa[i], sb[i]) then return false; end if;
  end loop;
  return true;
end $$;

-- several topics: one name per topic, all topics filled, one submission per phone; the same name may be in
-- different topics; within a topic a name near one already written counts for it
create or replace function public.poll_mwrite(p_token text, p_topics text[], p_names text[], p_voter text, p_poll uuid) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; i int; tid text; t text; nm text; k text; ks text[] := '{}'; es text[] := '{}'; tn int;
begin
  s := (select x from public.poll_sets x where x.vote_token = p_token);
  if s.id is not null then p := (select x from public.polls x where x.id = p_poll and x.set_id = s.id);
  else p := (select x from public.polls x where x.vote_token = p_token); end if;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if p.kind <> 'multi' or coalesce(length(p_voter), 0) not between 8 and 100 then return 'bad'; end if;
  tn := jsonb_array_length(p.options);
  if tn = 0 or coalesce(array_length(p_topics, 1), 0) <> tn or coalesce(array_length(p_names, 1), 0) <> tn then return 'bad'; end if;
  if (select count(distinct x) from unnest(p_topics) x where exists (select 1 from jsonb_array_elements(p.options) o where o->>'id' = x)) <> tn then return 'bad'; end if;
  perform pg_advisory_xact_lock(hashtext('poll_write:' || p.id::text));
  if exists (select 1 from public.poll_votes where poll_id = p.id and round = p.round and voter = p_voter) then return 'already'; end if;
  for i in 1..tn loop
    tid := p_topics[i];
    t := left(regexp_replace(btrim(coalesce(p_names[i], '')), '\s+', ' ', 'g'), 80);
    nm := public.poll_name_norm(t);
    if nm = '' then return 'bad'; end if;
    k := (select z.k from (select v.option_id k, count(*) c from public.poll_votes v
                             where v.poll_id = p.id and v.round = p.round and v.option_id like tid || ':%' group by v.option_id) z
           where public.poll_name_near(nm, public.poll_name_norm(substr(z.k, length(tid) + 4))) order by z.c desc, z.k limit 1);
    ks := ks || coalesce(k, tid || ':w:' || nm); es := es || t;
  end loop;
  insert into public.poll_votes (poll_id, round, option_id, voter, entry) select p.id, p.round, ks[j], p_voter, es[j] from generate_subscripts(ks, 1) j;
  return 'ok';
end $$;
revoke all on function public.poll_mwrite(text, text[], text[], text, uuid) from public;
grant execute on function public.poll_mwrite(text, text[], text[], text, uuid) to anon, authenticated;

-- Supabase: read the list of functions again (new ones are callable at once)
notify pgrst, 'reload schema';


-- ============================================================
-- Kanalo užduotys (chate → kanalas → „Užduotys“)
--  * užduotis gali priklausyti kanalui (tasks.conversation_id)
--  * kanalo užduotis mato visi kanalo nariai; atsakingas (kam paskirta)
--    pažymi „atlikta“ – užduotis pažaliuoja, neatlikta – raudona
--  * paskirta užduotis atsiranda ir atsakingo „Man paskirtos“ sąraše,
--    priminimai veikia kaip kitoms užduotims
-- Paleisti PO tasks.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

alter table public.tasks add column if not exists conversation_id uuid references public.conversations(id) on delete cascade;
create index if not exists tasks_conversation_idx on public.tasks (conversation_id);

-- mato: savo / paskirtas / kur atsakingas, ir visas savo kanalų užduotis
drop policy if exists "see my tasks" on public.tasks;
create policy "see my tasks" on public.tasks
  for select to authenticated
  using (created_by = auth.uid() or auth.uid() = any(assignees) or lead = auth.uid()
         or (conversation_id is not null and public.is_conv_member(conversation_id)));

-- kurti kanale gali tik to kanalo narys
drop policy if exists "create tasks" on public.tasks;
create policy "create tasks" on public.tasks
  for insert to authenticated
  with check (created_by = auth.uid() and public.is_approved()
              and (conversation_id is null or public.is_conv_member(conversation_id)));

-- Supabase: read the list of columns again
notify pgrst, 'reload schema';


-- ============================================================
-- Transportas: automobilį pašalinti iš parko galima tik su Admin+ patvirtinimu
--  * kas redaguoja „Transportą“, siunčia prašymą (su priežastimi)
--  * patvirtina ar atmeta kitas Admin+ narys (ne tas, kuris prašė)
--  * serveris neleidžia išsaugoti parko be automobilio, kurio pašalinimas
--    nepatvirtintas (net jei kas nors bandytų apeiti programėlę)
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.vehicle_removals (
  id              uuid primary key default gen_random_uuid(),
  vehicle_id      text not null,
  vehicle_name    text not null default '',
  plate           text,
  reason          text not null default '',
  status          text not null default 'pending' check (status in ('pending','approved','rejected','cancelled','done')),
  requested_by    uuid not null default auth.uid(),
  requested_name  text,
  requested_at    timestamptz not null default now(),
  decided_by      uuid,
  decided_name    text,
  decided_at      timestamptz,
  decision_note   text,
  task_id         uuid
);
create index if not exists vehicle_removals_vehicle on public.vehicle_removals (vehicle_id, status);
-- one open request per vehicle
create unique index if not exists vehicle_removals_open on public.vehicle_removals (vehicle_id) where status in ('pending','approved');

alter table public.vehicle_removals enable row level security;
drop policy if exists "vehicle removals view" on public.vehicle_removals;
create policy "vehicle removals view" on public.vehicle_removals for select to authenticated using (public.can_view('fleet'));
-- changes only through the functions below
revoke all on public.vehicle_removals from anon, authenticated;
grant select on public.vehicle_removals to authenticated;

create or replace function public.vehicle_rm_name() returns text language sql stable security definer set search_path = public as $$
  select coalesce(nullif(trim(coalesce(first_name, '') || ' ' || coalesce(last_name, '')), ''), nickname, split_part(email, '@', 1), 'Narys')
    from public.profiles where id = auth.uid()
$$;

-- the request (anyone who edits „Transportas“)
create or replace function public.vehicle_rm_request(vid text, vname text, vplate text, note text, tid uuid default null) returns public.vehicle_removals
  language plpgsql security definer set search_path = public as $$
declare r public.vehicle_removals;
begin
  if not public.can_edit('fleet') then raise exception 'Nėra teisės redaguoti transporto'; end if;
  if coalesce(trim(note), '') = '' then raise exception 'Parašyk priežastį'; end if;
  if exists (select 1 from public.vehicle_removals where vehicle_id = vid and status in ('pending','approved')) then
    raise exception 'Šiam automobiliui prašymas jau išsiųstas';
  end if;
  insert into public.vehicle_removals (vehicle_id, vehicle_name, plate, reason, requested_name, task_id)
    values (vid, left(coalesce(vname, ''), 200), left(vplate, 40), left(trim(note), 1000), public.vehicle_rm_name(), tid)
    returning * into r;
  return r;
end $$;

-- Admin+ decides – never on one's own request
create or replace function public.vehicle_rm_decide(rid uuid, approve boolean, note text default null) returns public.vehicle_removals
  language plpgsql security definer set search_path = public as $$
declare r public.vehicle_removals;
begin
  if not public.is_plus() then raise exception 'Patvirtinti gali tik Admin+'; end if;
  select * into r from public.vehicle_removals where id = rid for update;
  if r.id is null or r.status <> 'pending' then raise exception 'Prašymas jau išspręstas'; end if;
  if r.requested_by = auth.uid() then raise exception 'Savo prašymo patvirtinti negalima – tai daro kitas Admin+ narys'; end if;
  update public.vehicle_removals set status = case when approve then 'approved' else 'rejected' end,
    decided_by = auth.uid(), decided_name = public.vehicle_rm_name(), decided_at = now(), decision_note = nullif(trim(note), '')
    where id = rid returning * into r;
  return r;
end $$;

-- the one who asked (or Admin+) takes the request back
create or replace function public.vehicle_rm_cancel(rid uuid) returns public.vehicle_removals
  language plpgsql security definer set search_path = public as $$
declare r public.vehicle_removals;
begin
  select * into r from public.vehicle_removals where id = rid for update;
  if r.id is null or r.status not in ('pending','approved') then raise exception 'Prašymas jau išspręstas'; end if;
  if r.requested_by <> auth.uid() and not public.is_plus() then raise exception 'Atšaukti gali tik prašęs arba Admin+'; end if;
  update public.vehicle_removals set status = 'cancelled', decided_by = auth.uid(), decided_name = public.vehicle_rm_name(), decided_at = now()
    where id = rid returning * into r;
  return r;
end $$;

revoke all on function public.vehicle_rm_request(text, text, text, text, uuid) from public, anon;
revoke all on function public.vehicle_rm_decide(uuid, boolean, text) from public, anon;
revoke all on function public.vehicle_rm_cancel(uuid) from public, anon;
grant execute on function public.vehicle_rm_request(text, text, text, text, uuid) to authenticated;
grant execute on function public.vehicle_rm_decide(uuid, boolean, text) to authenticated;
grant execute on function public.vehicle_rm_cancel(uuid) to authenticated;

-- the guard: the fleet (app_state 'vehicles') may lose a vehicle only with an approved request
create or replace function public.vehicles_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
declare gone text[]; v text;
begin
  if auth.uid() is null then return coalesce(new, old); end if;          -- server jobs, SQL editor
  if tg_op = 'DELETE' then
    if old.key = 'vehicles' and jsonb_array_length(coalesce(old.data, '[]'::jsonb)) > 0 then
      raise exception 'Automobilį pašalinti galima tik su Admin+ patvirtinimu';
    end if;
    return old;
  end if;
  if new.key <> 'vehicles' or tg_op <> 'UPDATE' then return new; end if;
  gone := array(
    select o->>'id' from jsonb_array_elements(case when jsonb_typeof(old.data) = 'array' then old.data else '[]'::jsonb end) o
     where o->>'id' is not null
       and not exists (select 1 from jsonb_array_elements(case when jsonb_typeof(new.data) = 'array' then new.data else '[]'::jsonb end) n where n->>'id' = o->>'id'));
  foreach v in array gone loop
    if not exists (select 1 from public.vehicle_removals where vehicle_id = v and status = 'approved') then
      raise exception 'Automobilį pašalinti galima tik su Admin+ patvirtinimu';
    end if;
    update public.vehicle_removals set status = 'done' where vehicle_id = v and status = 'approved';
  end loop;
  return new;
end $$;
drop trigger if exists vehicles_guard on public.app_state;
create trigger vehicles_guard before update or delete on public.app_state
  for each row execute function public.vehicles_guard();

-- Supabase: read the list of tables and functions again
notify pgrst, 'reload schema';


-- ============================================================
-- Transportas → „UTA kortelės“
--  * uta_cards   – kuro kortelės: numeris, kam priskirta (transportui
--                  arba asmeniui), galiojimas, pastabos
--  * uta_reports – įkeltos mėnesio ataskaitos (Excel / CSV iš UTA)
--  * uta_tx      – ataskaitų eilutės: kada, kur, kas pilta, kiek, už kiek.
--                  Tas pats pylimas iš dviejų ataskaitų įrašomas tik kartą (key).
-- Mato visi, kas mato „Transportą“; keisti ir įkelti – kas jį redaguoja.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.uta_cards (
  id            uuid primary key default gen_random_uuid(),
  card_no       text not null check (length(card_no) between 4 and 40),
  title         text not null default '',
  assign_kind   text not null default 'none' check (assign_kind in ('vehicle','person','none')),
  vehicle_id    text,
  vehicle_name  text,
  person_id     uuid,
  person_name   text,
  valid_until   date,
  note          text not null default '',
  active        boolean not null default true,
  created_by    uuid default auth.uid(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
-- the same card once (spaces and dashes aside)
create unique index if not exists uta_cards_no on public.uta_cards (regexp_replace(card_no, '[^0-9A-Za-z]', '', 'g'));

create table if not exists public.uta_reports (
  id                uuid primary key default gen_random_uuid(),
  month             date not null,
  file_name         text not null default '',
  rows              integer not null default 0,
  uploaded_by       uuid default auth.uid(),
  uploaded_by_name  text,
  created_at        timestamptz not null default now()
);

create table if not exists public.uta_tx (
  id            uuid primary key default gen_random_uuid(),
  report_id     uuid references public.uta_reports(id) on delete cascade,
  card_no       text not null default '',
  card_id       uuid references public.uta_cards(id) on delete set null,
  tx_at         timestamptz not null,
  tx_date       date not null,
  plate         text,
  station       text,
  country       text,
  product       text,
  quantity      numeric(12,3),
  unit          text,
  amount_net    numeric(12,2),
  amount_gross  numeric(12,2),
  currency      text,
  mileage       integer,
  driver        text,
  key           text not null unique
);
create index if not exists uta_tx_date on public.uta_tx (tx_date);
create index if not exists uta_tx_card on public.uta_tx (card_id, tx_date);

alter table public.uta_cards enable row level security;
alter table public.uta_reports enable row level security;
alter table public.uta_tx enable row level security;

drop policy if exists "uta cards view" on public.uta_cards;
create policy "uta cards view" on public.uta_cards for select to authenticated using (public.can_view('fleet'));
drop policy if exists "uta cards edit" on public.uta_cards;
create policy "uta cards edit" on public.uta_cards for all to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));

drop policy if exists "uta reports view" on public.uta_reports;
create policy "uta reports view" on public.uta_reports for select to authenticated using (public.can_view('fleet'));
drop policy if exists "uta reports edit" on public.uta_reports;
create policy "uta reports edit" on public.uta_reports for all to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));

drop policy if exists "uta tx view" on public.uta_tx;
create policy "uta tx view" on public.uta_tx for select to authenticated using (public.can_view('fleet'));
drop policy if exists "uta tx edit" on public.uta_tx;
create policy "uta tx edit" on public.uta_tx for all to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));

revoke all on public.uta_cards, public.uta_reports, public.uta_tx from anon;
grant select, insert, update, delete on public.uta_cards, public.uta_reports, public.uta_tx to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';


-- ============================================================
-- Transportas → „Transporto nuoma“: nuomojamas transportas (mikroautobusai ir fūros)
--  * įmonė, transportas, valst. nr., išmatavimai, keliamoji galia,
--    paros nuomos kaina, kontaktai, pastabos
--  * „Kaip rašoma renginiuose“ – vardai / žodžiai (pvz. Alius), pagal kuriuos
--    Ataskaitos → Transporto nuoma pridės kainą ir kontaktus
-- Mato visi, kas mato „Transportą“; keisti – kas jį redaguoja.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.rent_vehicles (
  id            uuid primary key default gen_random_uuid(),
  kind          text not null default 'van' check (kind in ('van','truck')),
  company       text not null default '',
  name          text not null default '',
  plate         text,
  aliases       text not null default '',
  length_cm     numeric(8,1),
  width_cm      numeric(8,1),
  height_cm     numeric(8,1),
  max_kg        numeric(10,1),
  price_day     numeric(10,2),
  price_note    text not null default '',
  contact_name  text not null default '',
  phone         text not null default '',
  email         text not null default '',
  note          text not null default '',
  active        boolean not null default true,
  created_by    uuid default auth.uid(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

alter table public.rent_vehicles enable row level security;
drop policy if exists "rent vehicles view" on public.rent_vehicles;
create policy "rent vehicles view" on public.rent_vehicles for select to authenticated using (public.can_view('fleet') or public.can_view('stats'));
drop policy if exists "rent vehicles edit" on public.rent_vehicles;
create policy "rent vehicles edit" on public.rent_vehicles for all to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
revoke all on public.rent_vehicles from anon;
grant select, insert, update, delete on public.rent_vehicles to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';


-- ============================================================
-- Transporto nuoma, 2 dalis (paleisti po rent_vehicles.sql)
--  * source 'auto' – įrašas sukurtas pačios programos iš renginių transporto
--    (valst. nr., kurio nėra įmonės parke, arba „Fura Alius“)
--  * dismissed – ištrintas automatinis įrašas: paslepiamas ir iš renginių
--    nebepridedamas
--  * tas pats valst. nr. – tik vieną kartą
--  * trečias tipas: būdos (kind 'box') šalia mikroautobusų ir fūrų
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.rent_vehicles add column if not exists source text not null default 'manual';
alter table public.rent_vehicles add column if not exists dismissed boolean not null default false;
alter table public.rent_vehicles drop constraint if exists rent_vehicles_kind_check;
alter table public.rent_vehicles add constraint rent_vehicles_kind_check check (kind in ('van','box','truck'));
create unique index if not exists rent_vehicles_plate on public.rent_vehicles (upper(regexp_replace(plate, '[^A-Za-z0-9]', '', 'g'))) where plate is not null and plate <> '';

-- Supabase: read the list of columns again
notify pgrst, 'reload schema';


-- ============================================================
-- Transporto nuoma, 3 dalis (paleisti po rent_vehicles2.sql):
-- nuomojamo transporto nuotraukos ir dokumentai (nuomos sutartys, aktai…)
--  * kiekvienas įkėlimas – įrašas transporto istorijoje: data, pastaba, failai
--  * failai saugykloje 'fleet-files' (ta pati kaip tvarkymų),
--    kelias rent/<transporto id>/<įrašo id>/<failas>
-- Mato visi, kas mato „Transportą“ (ar Ataskaitas); įkelti ir trinti – kas redaguoja „Transportą“
-- (savo įkeltą įrašą ištrinti gali ir pats įkėlęs).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.rent_vehicle_docs (
  id               uuid primary key default gen_random_uuid(),
  rent_vehicle_id  uuid not null references public.rent_vehicles(id) on delete cascade,
  rent_date        date not null default current_date,
  note             text not null default '',
  files            jsonb not null default '[]'::jsonb,
  created_by       uuid not null default auth.uid(),
  created_by_name  text,
  created_at       timestamptz not null default now()
);
create index if not exists rent_vehicle_docs_vehicle on public.rent_vehicle_docs (rent_vehicle_id, rent_date desc);

alter table public.rent_vehicle_docs enable row level security;
drop policy if exists "rent docs view" on public.rent_vehicle_docs;
create policy "rent docs view" on public.rent_vehicle_docs for select to authenticated using (public.can_view('fleet') or public.can_view('stats'));
drop policy if exists "rent docs add" on public.rent_vehicle_docs;
create policy "rent docs add" on public.rent_vehicle_docs for insert to authenticated with check (public.can_edit('fleet') and created_by = auth.uid());
drop policy if exists "rent docs change" on public.rent_vehicle_docs;
create policy "rent docs change" on public.rent_vehicle_docs for update to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
drop policy if exists "rent docs delete" on public.rent_vehicle_docs;
create policy "rent docs delete" on public.rent_vehicle_docs for delete to authenticated using (public.can_edit('fleet') or created_by = auth.uid());
revoke all on public.rent_vehicle_docs from anon;
grant select, insert, update, delete on public.rent_vehicle_docs to authenticated;

-- the storage (the same as vehicle_logs.sql, in case that one was not run)
insert into storage.buckets (id, name, public) values ('fleet-files', 'fleet-files', false) on conflict (id) do nothing;
drop policy if exists "fleet files view" on storage.objects;
create policy "fleet files view" on storage.objects for select to authenticated
  using (bucket_id = 'fleet-files' and (public.can_view('fleet') or public.can_view('stats')));
drop policy if exists "fleet files add" on storage.objects;
create policy "fleet files add" on storage.objects for insert to authenticated
  with check (bucket_id = 'fleet-files' and public.can_view('fleet'));
drop policy if exists "fleet files delete" on storage.objects;
create policy "fleet files delete" on storage.objects for delete to authenticated
  using (bucket_id = 'fleet-files' and (public.can_edit('fleet') or owner = auth.uid()));

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';


-- ============================================================
-- Sandėlis → „Atlikti darbai“: valymas, profilaktinė patikra, remontas…
--  * įrašas: kada, koks darbas, su kuriais daiktais (ar visa grupe),
--    kas darė, pastaba, nuotraukos
--  * nuotraukos saugykloje 'equipment-photos', kelias works/<įrašo id>/<failas>
-- Mato visi, kas mato „Sandėlį“; registruoti – kas redaguoja „Sandėlį“
-- (savo įrašą pataisyti / ištrinti gali ir pats įrašęs).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.item_works (
  id               uuid primary key default gen_random_uuid(),
  work_date        date not null default current_date,
  kind             text not null default '',
  item_ids         text[] not null default '{}',
  item_names       text[] not null default '{}',
  scope            text not null default '',      -- a whole group / subgroup, e.g. „Garsas › Kolonėlės“
  done_by          text[] not null default '{}',  -- who did it (names)
  note             text not null default '',
  files            jsonb not null default '[]'::jsonb,
  created_by       uuid not null default auth.uid(),
  created_by_name  text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);
create index if not exists item_works_date on public.item_works (work_date desc);

alter table public.item_works enable row level security;
drop policy if exists "item works view" on public.item_works;
create policy "item works view" on public.item_works for select to authenticated using (public.can_view('inventory'));
drop policy if exists "item works add" on public.item_works;
create policy "item works add" on public.item_works for insert to authenticated with check (public.can_edit('inventory') and created_by = auth.uid());
drop policy if exists "item works change" on public.item_works;
create policy "item works change" on public.item_works for update to authenticated using (public.can_edit('inventory') or created_by = auth.uid()) with check (public.can_edit('inventory') or created_by = auth.uid());
drop policy if exists "item works delete" on public.item_works;
create policy "item works delete" on public.item_works for delete to authenticated using (public.can_edit('inventory') or created_by = auth.uid());
revoke all on public.item_works from anon;
grant select, insert, update, delete on public.item_works to authenticated;

-- photos: equipment-photos/works/… – seen by who sees Sandėlis, added by who edits it
create or replace function public.equipment_photo_access(obj_name text, edit boolean) returns boolean
  language sql stable security definer set search_path = public as $$
  select case (storage.foldername(obj_name))[1]
    when 'rentals'   then case when edit then public.can_edit('rentals')   else public.can_view('rentals')   end
    when 'handovers' then case when edit then public.can_edit('handovers') else public.can_view('handovers') end
    when 'gear'      then public.can_view('inventory')
    when 'works'     then case when edit then public.can_edit('inventory') else public.can_view('inventory') end
    else false end
$$;
grant execute on function public.equipment_photo_access(text, boolean) to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';


-- ============================================================
-- Žmonės 5: žyma „Perskambinti“ — žmogus paprašė perskambinti ir
-- pasitikslinti dėl dienos (rodoma Žmonės → Užimtumas).
-- Paleisti PO people4.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.contact_calls drop constraint if exists contact_calls_outcome_check;
alter table public.contact_calls add constraint contact_calls_outcome_check
  check (outcome in ('calling','sutiko','atsisake','negali','placiau','neatsiliepe','gali','perskambinti'));


-- ============================================================
-- El. paštas: laiškai atsidaro iš karto
--  * mail_bodies – naujausių laiškų turinys (tekstas, priedų sąrašas);
--    „mail“ funkcija jį parsisiunčia fone (kartu su laiškų sąrašu, kas minutę),
--    o programa laišką atidaro iš čia – nelaukdama pašto serverio.
--    Laikoma tik ~60 naujausių kiekviename aplanke; senesni skaitomi kaip anksčiau.
--  * kiekvienas mato TIK SAVO laiškus; rašo tik serverio funkcija
-- Reikia: „mail“ funkcija v12 (supabase functions deploy mail).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.mail_bodies (
  user_id    uuid not null references auth.users(id) on delete cascade,
  folder     text not null,
  uid        bigint not null,
  data       jsonb not null,
  fetched_at timestamptz not null default now(),
  primary key (user_id, folder, uid)
);

alter table public.mail_bodies enable row level security;
drop policy if exists "own mail bodies" on public.mail_bodies;
create policy "own mail bodies" on public.mail_bodies for select to authenticated using (user_id = auth.uid());
revoke all on public.mail_bodies from anon;
revoke insert, update, delete on public.mail_bodies from authenticated;
grant select on public.mail_bodies to authenticated;

-- atsijungus nuo pašto – ir laiškų turinys ištrinamas
create or replace function public.mail_bodies_cleanup() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  delete from public.mail_bodies where user_id = old.user_id;
  return old;
end $$;
drop trigger if exists mail_bodies_cleanup on public.mail_accounts;
create trigger mail_bodies_cleanup after delete on public.mail_accounts
  for each row execute function public.mail_bodies_cleanup();


-- ============================================================
-- „Pirkiniai“: pirkinių skiltys (kaip Excel lapai: VIDEO, LIGHT, AUDIO, Bendri daiktai…)
--  * viena eilutė = viena skiltis; jos lentelė (eilutės, langeliai, formulės) – rows (jsonb)
--  * vieša (visible = 'public') – mato visi, kam leista „Pirkiniai“, keisti gali kas juos redaguoja;
--    tik man (visible = 'private') – mato ir keičia tik sukūręs
--  * viešumą ir pavadinimą keičia tik savininkas (ar administratorius)
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- skiltis „Pirkiniai“ teisių lentelėje ----------
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people','newproj','invoices','buy'));
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','buy',true,true), ('office','buy',true,true), ('tech','buy',true,true),
  ('freelance','buy',false,false), ('runner','buy',false,false)
on conflict (role, section) do nothing;

create table if not exists public.purchase_lists (
  id               uuid primary key default gen_random_uuid(),
  name             text not null default 'Nauja skiltis',
  visible          text not null default 'public' check (visible in ('public','private')),
  owner            uuid not null default auth.uid() references auth.users(id) on delete cascade,
  owner_name       text,
  sort             integer not null default 0,
  cols             jsonb not null default '[]'::jsonb,   -- column titles (A…H)
  rows             jsonb not null default '[]'::jsonb,   -- [{id, sec?, c:{A:'…', B:'=…'}}]
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  updated_by       uuid,
  updated_by_name  text
);
create index if not exists purchase_lists_sort on public.purchase_lists (sort, created_at);

create or replace function public.purchase_lists_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'UPDATE' and old.owner <> auth.uid() and not public.is_admin() then
    if new.owner <> old.owner or new.visible <> old.visible or new.name <> old.name then
      raise exception 'Pavadinimą ir matomumą keičia tik skilties savininkas.';
    end if;
  end if;
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end $$;
drop trigger if exists purchase_lists_guard on public.purchase_lists;
create trigger purchase_lists_guard before insert or update on public.purchase_lists
  for each row execute function public.purchase_lists_guard();

alter table public.purchase_lists enable row level security;
drop policy if exists "purchase lists view" on public.purchase_lists;
create policy "purchase lists view" on public.purchase_lists for select to authenticated
  using (owner = auth.uid() or (visible = 'public' and public.can_view('buy')));
drop policy if exists "purchase lists add" on public.purchase_lists;
create policy "purchase lists add" on public.purchase_lists for insert to authenticated
  with check (owner = auth.uid() and (public.can_edit('buy') or (visible = 'private' and public.can_view('buy'))));
drop policy if exists "purchase lists change" on public.purchase_lists;
create policy "purchase lists change" on public.purchase_lists for update to authenticated
  using (owner = auth.uid() or (visible = 'public' and public.can_edit('buy')))
  with check (owner = auth.uid() or (visible = 'public' and public.can_edit('buy')));
drop policy if exists "purchase lists delete" on public.purchase_lists;
create policy "purchase lists delete" on public.purchase_lists for delete to authenticated
  using (owner = auth.uid() or public.is_admin());
revoke all on public.purchase_lists from anon;
grant select, insert, update, delete on public.purchase_lists to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';


-- ============================================================
-- „Team Tracker“: darbo laiko apskaita (kaip Connecteam „Time Clock“)
--  * tracker_members – Team Tracker nariai: vardas ir PIN kodas (PIN saugomas tik
--                      kaip maiša). Kiekvienas narys prisijungia atskirai savo PIN,
--                      tame pačiame telefone gali dirbti keli nariai.
--  * time_shifts     – pamaina: nuo „Pradėti darbą“ iki „Baigti darbą“
--  * time_entries    – pamainos dalys: sandėlis, vairavimas, budėjimas, montažas,
--                      demontažas, operatorius, pertrauka
--  * visiems matoma tik narių sąrašas (kiek užregistruota); nario laikas – tik
--    prisijungus jo PIN (administratoriui – be PIN)
--  * viskas tik per funkcijas tt_* (lentelių tiesiogiai neskaito niekas);
--    5 neteisingi PIN – 5 min. palaukti
--  * kas valandą priminimą „Team Tracker aktyvus“ siunčia push-notify (jau veikiantis
--    kas 5 min. darbas) – po šio failo iš naujo įdiek funkciją push-notify
--  * pridedamas „Demo darbuotojas“ (PIN 0000) su atsitiktinėmis 2 savaičių pamainomis
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.tracker_members (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  pin_hash      text not null,
  demo          boolean not null default false,
  fails         integer not null default 0,
  locked_until  timestamptz,
  created_by    uuid default auth.uid(),
  created_at    timestamptz not null default now()
);
create unique index if not exists tracker_members_name on public.tracker_members (lower(name));

create table if not exists public.tracker_tokens (
  token_hash  text primary key,
  member_id   uuid not null references public.tracker_members(id) on delete cascade,
  user_id     uuid default auth.uid(),
  created_at  timestamptz not null default now()
);

create table if not exists public.time_shifts (
  id           uuid primary key default gen_random_uuid(),
  member_id    uuid not null references public.tracker_members(id) on delete cascade,
  started_by   uuid,                       -- the app account that pressed „Pradėti“ (gets the reminders)
  started_at   timestamptz not null default now(),
  ended_at     timestamptz,
  reminded_at  timestamptz,
  created_at   timestamptz not null default now()
);
create index if not exists time_shifts_member_time on public.time_shifts (member_id, started_at desc);
create unique index if not exists time_shifts_one_open on public.time_shifts (member_id) where ended_at is null;

create table if not exists public.time_entries (
  id          uuid primary key default gen_random_uuid(),
  shift_id    uuid not null references public.time_shifts(id) on delete cascade,
  kind        text not null check (kind in ('warehouse','driving','standby','setup','teardown','operator','break')),
  started_at  timestamptz not null default now(),
  ended_at    timestamptz
);
create index if not exists time_entries_shift on public.time_entries (shift_id, started_at);
create unique index if not exists time_entries_one_open on public.time_entries (shift_id) where ended_at is null;

alter table public.tracker_members enable row level security;
alter table public.tracker_tokens enable row level security;
alter table public.time_shifts enable row level security;
alter table public.time_entries enable row level security;
revoke all on public.tracker_members, public.tracker_tokens, public.time_shifts, public.time_entries from anon, authenticated;

-- ---------- pagalbinės ----------
-- PIN or the device's sign-in key (token); null = allowed. Admin may pass nothing (to look and delete).
create or replace function public.tt_auth(m uuid, p_pin text, p_token text, admin_ok boolean) returns text
  language plpgsql security definer set search_path = public, extensions as $$
declare r public.tracker_members;
begin
  if auth.uid() is null or not public.is_approved() then return 'Reikia prisijungti prie programėlės.'; end if;
  select * into r from public.tracker_members where id = m;
  if r.id is null then return 'Tokio nario nėra.'; end if;
  if p_token is not null and exists (select 1 from public.tracker_tokens where member_id = m and token_hash = encode(digest(p_token, 'sha256'), 'hex')) then return null; end if;
  if p_pin is null then
    if admin_ok and public.is_admin() then return null; end if;
    return 'Prisijunk savo PIN kodu.';
  end if;
  if r.locked_until is not null and r.locked_until > now() then return 'Per daug neteisingų bandymų – palauk kelias minutes.'; end if;
  if r.pin_hash = crypt(p_pin, r.pin_hash) then
    update public.tracker_members set fails = 0, locked_until = null where id = m;
    return null;
  end if;
  update public.tracker_members set fails = case when fails >= 4 then 0 else fails + 1 end,
    locked_until = case when fails >= 4 then now() + interval '5 minutes' else locked_until end where id = m;
  return 'Neteisingas PIN kodas.';
end $$;

create or replace function public.tt_shift_json(sid uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', s.id, 'started_at', s.started_at, 'ended_at', s.ended_at,
    'entries', coalesce((select jsonb_agg(jsonb_build_object('kind', e.kind, 'started_at', e.started_at, 'ended_at', e.ended_at) order by e.started_at)
                         from public.time_entries e where e.shift_id = s.id), '[]'::jsonb))
  from public.time_shifts s where s.id = sid
$$;

create or replace function public.tt_state_of(m uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shift', (select public.tt_shift_json(id) from public.time_shifts where member_id = m and ended_at is null),
    'last', (select public.tt_shift_json(id) from public.time_shifts where member_id = m and ended_at is not null order by ended_at desc limit 1))
$$;

-- ---------- visiems: narių sąrašas (kiek užregistruota) ----------
create or replace function public.tt_members() returns jsonb
  language sql stable security definer set search_path = public as $$
  select case when public.is_approved() then coalesce((select jsonb_agg(jsonb_build_object('id', id, 'name', name, 'demo', demo, 'created_at', created_at) order by demo, lower(name)) from public.tracker_members), '[]'::jsonb) else '[]'::jsonb end
$$;

create or replace function public.tt_register(p_name text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare nm text := btrim(coalesce(p_name, '')); mid uuid; tok text;
begin
  if auth.uid() is null or not public.is_approved() then return jsonb_build_object('error', 'Reikia prisijungti prie programėlės.'); end if;
  if length(nm) < 2 or length(nm) > 60 then return jsonb_build_object('error', 'Įrašyk vardą ir pavardę.'); end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4,8}$' then return jsonb_build_object('error', 'PIN – 4–8 skaitmenys.'); end if;
  if exists (select 1 from public.tracker_members where lower(name) = lower(nm)) then return jsonb_build_object('error', 'Toks narys jau užregistruotas.'); end if;
  insert into public.tracker_members (name, pin_hash) values (nm, crypt(p_pin, gen_salt('bf'))) returning id into mid;
  tok := encode(gen_random_bytes(24), 'hex');
  insert into public.tracker_tokens (token_hash, member_id) values (encode(digest(tok, 'sha256'), 'hex'), mid);
  return jsonb_build_object('token', tok, 'state', public.tt_state_of(mid));
end $$;

-- prisijungimas PIN kodu: šiam įrenginiui grąžinamas raktas (PIN neįsimenamas)
create or replace function public.tt_login(m uuid, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; tok text;
begin
  err := public.tt_auth(m, coalesce(p_pin, ''), null, false);
  if err is not null then return jsonb_build_object('error', err); end if;
  tok := encode(gen_random_bytes(24), 'hex');
  insert into public.tracker_tokens (token_hash, member_id) values (encode(digest(tok, 'sha256'), 'hex'), m);
  return jsonb_build_object('token', tok, 'state', public.tt_state_of(m));
end $$;

create or replace function public.tt_logout(m uuid, p_token text) returns void
  language sql security definer set search_path = public, extensions as $$
  delete from public.tracker_tokens where member_id = m and token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
$$;

create or replace function public.tt_state(m uuid, p_token text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return public.tt_state_of(m);
end $$;

-- „Pradėti darbą“
create or replace function public.tt_start(m uuid, p_token text, p_kind text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  if exists (select 1 from public.time_shifts where member_id = m and ended_at is null) then return public.tt_state_of(m); end if;
  insert into public.time_shifts (member_id, started_by) values (m, auth.uid()) returning id into sid;
  insert into public.time_entries (shift_id, kind) values (sid, p_kind);
  return public.tt_state_of(m);
end $$;

-- veiklos pakeitimas: ankstesnė užbaigiama ir išsaugoma, nauja pradedama dabar
create or replace function public.tt_switch(m uuid, p_token text, p_kind text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid; cur text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select id into sid from public.time_shifts where member_id = m and ended_at is null;
  if sid is null then return jsonb_build_object('error', 'Darbas nepradėtas.'); end if;
  select kind into cur from public.time_entries where shift_id = sid and ended_at is null;
  if cur is distinct from p_kind then
    update public.time_entries set ended_at = now() where shift_id = sid and ended_at is null;
    insert into public.time_entries (shift_id, kind) values (sid, p_kind);
  end if;
  return public.tt_state_of(m);
end $$;

-- „Baigti darbą“ (p_at – jei pamiršai baigti: ankstesnis laikas, bet ne ankstesnis už paskutinės veiklos pradžią)
create or replace function public.tt_stop(m uuid, p_token text, p_at timestamptz default null) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid; last_start timestamptz; t timestamptz;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select id into sid from public.time_shifts where member_id = m and ended_at is null;
  if sid is null then return public.tt_state_of(m); end if;
  select max(started_at) into last_start from public.time_entries where shift_id = sid;
  t := least(now(), greatest(coalesce(p_at, now()), coalesce(last_start, now())));
  update public.time_entries set ended_at = t where shift_id = sid and ended_at is null;
  update public.time_shifts set ended_at = t where id = sid;
  return public.tt_state_of(m);
end $$;

-- nario pamainos per laikotarpį (prisijungus; administratoriui – be PIN)
create or replace function public.tt_report(m uuid, p_token text, p_from timestamptz, p_to timestamptz) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, true);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shifts', coalesce((select jsonb_agg(public.tt_shift_json(s.id) order by s.started_at desc) from public.time_shifts s
       where s.member_id = m and s.started_at < p_to and coalesce(s.ended_at, now()) > p_from), '[]'::jsonb));
end $$;

-- nario ištrynimas su visu jo laiku: pats narys (PIN / raktu) arba administratorius
create or replace function public.tt_delete(m uuid, p_token text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, p_pin, p_token, true);
  if err is not null then return jsonb_build_object('error', err); end if;
  delete from public.tracker_members where id = m;
  return jsonb_build_object('ok', true);
end $$;

revoke all on function public.tt_auth(uuid, text, text, boolean), public.tt_shift_json(uuid), public.tt_state_of(uuid) from public, anon, authenticated;
revoke all on function public.tt_members(), public.tt_register(text, text), public.tt_login(uuid, text), public.tt_logout(uuid, text),
  public.tt_state(uuid, text), public.tt_start(uuid, text, text), public.tt_switch(uuid, text, text), public.tt_stop(uuid, text, timestamptz),
  public.tt_report(uuid, text, timestamptz, timestamptz), public.tt_delete(uuid, text, text) from public, anon;
grant execute on function public.tt_members(), public.tt_register(text, text), public.tt_login(uuid, text), public.tt_logout(uuid, text),
  public.tt_state(uuid, text), public.tt_start(uuid, text, text), public.tt_switch(uuid, text, text), public.tt_stop(uuid, text, timestamptz),
  public.tt_report(uuid, text, timestamptz, timestamptz), public.tt_delete(uuid, text, text) to authenticated;

-- ---------- demo darbuotojas: 2 savaičių darbo dienos su atsitiktinėmis veiklomis ----------
do $$
declare mid uuid; d date; t timestamptz; sid uuid; k text; n int; i int; dur int; br boolean;
  kinds text[] := array['warehouse','driving','standby','setup','teardown','operator'];
begin
  if exists (select 1 from public.tracker_members where demo) then return; end if;
  insert into public.tracker_members (name, pin_hash, demo, created_by)
    values ('Demo darbuotojas', extensions.crypt('0000', extensions.gen_salt('bf')), true, null) returning id into mid;
  for d in select generate_series(current_date - 14, current_date - 1, interval '1 day')::date loop
    continue when extract(isodow from d) in (6, 7);
    t := (d + time '07:30' + make_interval(mins => (random() * 90)::int)) at time zone 'Europe/Vilnius';
    insert into public.time_shifts (member_id, started_at) values (mid, t) returning id into sid;
    n := 3 + (random() * 3)::int; br := false;
    for i in 1..n loop
      if not br and i > 1 and random() < 0.6 then
        k := 'break'; dur := 20 + (random() * 25)::int; br := true;
      else
        k := kinds[1 + (random() * 5)::int]; dur := 45 + (random() * 150)::int;
      end if;
      insert into public.time_entries (shift_id, kind, started_at, ended_at) values (sid, k, t, t + make_interval(mins => dur));
      t := t + make_interval(mins => dur);
    end loop;
    update public.time_shifts set ended_at = t where id = sid;
  end loop;
end $$;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';


-- ============================================================
-- „Team Tracker“: darbo laiko apskaita (kaip Connecteam „Time Clock“)
--  * tracker_members – Team Tracker nariai: vardas ir PIN kodas (PIN saugomas tik
--                      kaip maiša). Kiekvienas narys prisijungia atskirai savo PIN,
--                      tame pačiame telefone gali dirbti keli nariai.
--  * time_shifts     – pamaina: nuo „Pradėti darbą“ iki „Baigti darbą“
--  * time_entries    – pamainos dalys: sandėlis, vairavimas, budėjimas, montažas,
--                      demontažas, operatorius, pertrauka
--  * narys susietas su programėlės paskyra: viena paskyra – vienas narys (registruojasi vieną kartą)
--  * visiems matoma tik narių sąrašas (kiek užregistruota). Nario laiką mato pats narys
--    (savo paskyra arba prisijungęs jo PIN); Admin, Office ir Projektų vadovai – visų narių
--    (be PIN); Tech, Freelance, Runner – tik savo
--  * pamiršus PIN: į paskyros el. paštą siunčiama nuoroda (galioja 1 val.) – ją siunčia
--    funkcija push-notify (RESEND_API_KEY), PIN pakeičiamas per tt_pin_reset
--  * viskas tik per funkcijas tt_* (lentelių tiesiogiai neskaito niekas);
--    5 neteisingi PIN – 5 min. palaukti
--  * kas valandą priminimą „Team Tracker aktyvus“ siunčia push-notify (jau veikiantis
--    kas 5 min. darbas) – po šio failo iš naujo įdiek funkciją push-notify
--  * pridedamas „Demo darbuotojas“ (PIN 0000) su atsitiktinėmis 2 savaičių pamainomis
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.tracker_members (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  pin_hash      text not null,
  demo          boolean not null default false,
  fails         integer not null default 0,
  locked_until  timestamptz,
  created_by    uuid default auth.uid(),
  created_at    timestamptz not null default now()
);
create unique index if not exists tracker_members_name on public.tracker_members (lower(name));
alter table public.tracker_members add column if not exists user_id uuid references auth.users(id) on delete set null;
alter table public.tracker_members add column if not exists reset_sent_at timestamptz;
create unique index if not exists tracker_members_user on public.tracker_members (user_id) where user_id is not null;

-- „Pamiršau PIN“: vienkartinės nuorodos (galioja 1 val.)
create table if not exists public.tracker_pin_resets (
  token_hash  text primary key,
  member_id   uuid not null references public.tracker_members(id) on delete cascade,
  expires_at  timestamptz not null default now() + interval '1 hour',
  used_at     timestamptz,
  created_at  timestamptz not null default now()
);
alter table public.tracker_pin_resets enable row level security;
revoke all on public.tracker_pin_resets from anon, authenticated;

create table if not exists public.tracker_tokens (
  token_hash  text primary key,
  member_id   uuid not null references public.tracker_members(id) on delete cascade,
  user_id     uuid default auth.uid(),
  created_at  timestamptz not null default now()
);

create table if not exists public.time_shifts (
  id           uuid primary key default gen_random_uuid(),
  member_id    uuid not null references public.tracker_members(id) on delete cascade,
  started_by   uuid,                       -- the app account that pressed „Pradėti“ (gets the reminders)
  started_at   timestamptz not null default now(),
  ended_at     timestamptz,
  reminded_at  timestamptz,
  created_at   timestamptz not null default now()
);
create index if not exists time_shifts_member_time on public.time_shifts (member_id, started_at desc);
create unique index if not exists time_shifts_one_open on public.time_shifts (member_id) where ended_at is null;

create table if not exists public.time_entries (
  id          uuid primary key default gen_random_uuid(),
  shift_id    uuid not null references public.time_shifts(id) on delete cascade,
  kind        text not null check (kind in ('warehouse','driving','standby','setup','teardown','operator','break')),
  started_at  timestamptz not null default now(),
  ended_at    timestamptz
);
create index if not exists time_entries_shift on public.time_entries (shift_id, started_at);
create unique index if not exists time_entries_one_open on public.time_entries (shift_id) where ended_at is null;

alter table public.tracker_members enable row level security;
alter table public.tracker_tokens enable row level security;
alter table public.time_shifts enable row level security;
alter table public.time_entries enable row level security;
revoke all on public.tracker_members, public.tracker_tokens, public.time_shifts, public.time_entries from anon, authenticated;

-- ---------- pagalbinės ----------
-- who may see every member's time: Admin, Office, Projektų vadovas (Tech, Freelance, Runner – only their own)
create or replace function public.tt_manager() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','office','pm'), false)
$$;
-- PIN or the device's sign-in key (token); null = allowed. A manager / the member's own account may pass nothing (to look).
create or replace function public.tt_auth(m uuid, p_pin text, p_token text, admin_ok boolean) returns text
  language plpgsql security definer set search_path = public, extensions as $$
declare r public.tracker_members;
begin
  if auth.uid() is null or not public.is_approved() then return 'Reikia prisijungti prie programėlės.'; end if;
  select * into r from public.tracker_members where id = m;
  if r.id is null then return 'Tokio nario nėra.'; end if;
  if p_token is not null and exists (select 1 from public.tracker_tokens where member_id = m and token_hash = encode(digest(p_token, 'sha256'), 'hex')) then return null; end if;
  if p_pin is null then
    -- looking at the time (admin_ok): the member's own account, or Admin / Office / Projektų vadovas
    if admin_ok and (r.user_id = auth.uid() or public.tt_manager()) then return null; end if;
    return 'Prisijunk savo PIN kodu.';
  end if;
  if r.locked_until is not null and r.locked_until > now() then return 'Per daug neteisingų bandymų – palauk kelias minutes.'; end if;
  if r.pin_hash = crypt(p_pin, r.pin_hash) then
    update public.tracker_members set fails = 0, locked_until = null where id = m;
    return null;
  end if;
  update public.tracker_members set fails = case when fails >= 4 then 0 else fails + 1 end,
    locked_until = case when fails >= 4 then now() + interval '5 minutes' else locked_until end where id = m;
  return 'Neteisingas PIN kodas.';
end $$;

create or replace function public.tt_shift_json(sid uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', s.id, 'started_at', s.started_at, 'ended_at', s.ended_at,
    'entries', coalesce((select jsonb_agg(jsonb_build_object('kind', e.kind, 'started_at', e.started_at, 'ended_at', e.ended_at) order by e.started_at)
                         from public.time_entries e where e.shift_id = s.id), '[]'::jsonb))
  from public.time_shifts s where s.id = sid
$$;

create or replace function public.tt_state_of(m uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shift', (select public.tt_shift_json(id) from public.time_shifts where member_id = m and ended_at is null),
    'last', (select public.tt_shift_json(id) from public.time_shifts where member_id = m and ended_at is not null order by ended_at desc limit 1))
$$;

-- ---------- visiems: narių sąrašas (kiek užregistruota) ----------
create or replace function public.tt_members() returns jsonb
  language sql stable security definer set search_path = public as $$
  select case when public.is_approved() then coalesce((select jsonb_agg(jsonb_build_object('id', id, 'name', name, 'demo', demo, 'created_at', created_at, 'mine', user_id = auth.uid(), 'mail', user_id is not null) order by demo, lower(name)) from public.tracker_members), '[]'::jsonb) else '[]'::jsonb end
$$;

create or replace function public.tt_register(p_name text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare nm text := btrim(coalesce(p_name, '')); mid uuid; tok text;
begin
  if auth.uid() is null or not public.is_approved() then return jsonb_build_object('error', 'Reikia prisijungti prie programėlės.'); end if;
  if length(nm) < 2 or length(nm) > 60 then return jsonb_build_object('error', 'Įrašyk vardą ir pavardę.'); end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4,8}$' then return jsonb_build_object('error', 'PIN – 4–8 skaitmenys.'); end if;
  if exists (select 1 from public.tracker_members where user_id = auth.uid()) then return jsonb_build_object('error', 'Tu jau užregistruotas Team Tracker – prisijunk savo PIN (pamiršus – „Pamiršau PIN“).'); end if;
  if exists (select 1 from public.tracker_members where lower(name) = lower(nm)) then return jsonb_build_object('error', 'Toks narys jau užregistruotas.'); end if;
  insert into public.tracker_members (name, pin_hash, user_id) values (nm, crypt(p_pin, gen_salt('bf')), auth.uid()) returning id into mid;
  tok := encode(gen_random_bytes(24), 'hex');
  insert into public.tracker_tokens (token_hash, member_id) values (encode(digest(tok, 'sha256'), 'hex'), mid);
  return jsonb_build_object('token', tok, 'state', public.tt_state_of(mid));
end $$;

-- prisijungimas PIN kodu: šiam įrenginiui grąžinamas raktas (PIN neįsimenamas)
create or replace function public.tt_login(m uuid, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; tok text;
begin
  err := public.tt_auth(m, coalesce(p_pin, ''), null, false);
  if err is not null then return jsonb_build_object('error', err); end if;
  -- a member registered before accounts were linked: tied to the first account that signs in with the PIN
  update public.tracker_members set user_id = auth.uid()
   where id = m and user_id is null and not demo and not exists (select 1 from public.tracker_members where user_id = auth.uid());
  tok := encode(gen_random_bytes(24), 'hex');
  insert into public.tracker_tokens (token_hash, member_id) values (encode(digest(tok, 'sha256'), 'hex'), m);
  return jsonb_build_object('token', tok, 'state', public.tt_state_of(m));
end $$;

create or replace function public.tt_logout(m uuid, p_token text) returns void
  language sql security definer set search_path = public, extensions as $$
  delete from public.tracker_tokens where member_id = m and token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
$$;

create or replace function public.tt_state(m uuid, p_token text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return public.tt_state_of(m);
end $$;

-- „Pradėti darbą“
create or replace function public.tt_start(m uuid, p_token text, p_kind text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  if exists (select 1 from public.time_shifts where member_id = m and ended_at is null) then return public.tt_state_of(m); end if;
  insert into public.time_shifts (member_id, started_by) values (m, auth.uid()) returning id into sid;
  insert into public.time_entries (shift_id, kind) values (sid, p_kind);
  return public.tt_state_of(m);
end $$;

-- veiklos pakeitimas: ankstesnė užbaigiama ir išsaugoma, nauja pradedama dabar
create or replace function public.tt_switch(m uuid, p_token text, p_kind text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid; cur text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select id into sid from public.time_shifts where member_id = m and ended_at is null;
  if sid is null then return jsonb_build_object('error', 'Darbas nepradėtas.'); end if;
  select kind into cur from public.time_entries where shift_id = sid and ended_at is null;
  if cur is distinct from p_kind then
    update public.time_entries set ended_at = now() where shift_id = sid and ended_at is null;
    insert into public.time_entries (shift_id, kind) values (sid, p_kind);
  end if;
  return public.tt_state_of(m);
end $$;

-- „Baigti darbą“ (p_at – jei pamiršai baigti: ankstesnis laikas, bet ne ankstesnis už paskutinės veiklos pradžią)
create or replace function public.tt_stop(m uuid, p_token text, p_at timestamptz default null) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid; last_start timestamptz; t timestamptz;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select id into sid from public.time_shifts where member_id = m and ended_at is null;
  if sid is null then return public.tt_state_of(m); end if;
  select max(started_at) into last_start from public.time_entries where shift_id = sid;
  t := least(now(), greatest(coalesce(p_at, now()), coalesce(last_start, now())));
  update public.time_entries set ended_at = t where shift_id = sid and ended_at is null;
  update public.time_shifts set ended_at = t where id = sid;
  return public.tt_state_of(m);
end $$;

-- nario pamainos per laikotarpį (prisijungus; administratoriui – be PIN)
create or replace function public.tt_report(m uuid, p_token text, p_from timestamptz, p_to timestamptz) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, true);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shifts', coalesce((select jsonb_agg(public.tt_shift_json(s.id) order by s.started_at desc) from public.time_shifts s
       where s.member_id = m and s.started_at < p_to and coalesce(s.ended_at, now()) > p_from), '[]'::jsonb));
end $$;

-- nario ištrynimas su visu jo laiku: pats narys (savo paskyra / PIN / raktu) arba administratorius
create or replace function public.tt_delete(m uuid, p_token text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  if public.is_admin() or exists (select 1 from public.tracker_members where id = m and user_id = auth.uid()) then err := null;
  else err := public.tt_auth(m, p_pin, p_token, false); end if;
  if err is not null then return jsonb_build_object('error', err); end if;
  delete from public.tracker_members where id = m;
  return jsonb_build_object('ok', true);
end $$;

-- naujas PIN pagal nuorodą iš laiško (veikia ir neprisijungus prie programėlės; nuoroda vienkartinė, 1 val.)
create or replace function public.tt_pin_reset(p_token text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare r public.tracker_pin_resets; nm text;
begin
  select * into r from public.tracker_pin_resets where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  if r.token_hash is null or r.used_at is not null then return jsonb_build_object('error', 'Nuoroda neteisinga arba jau panaudota.'); end if;
  if r.expires_at < now() then return jsonb_build_object('error', 'Nuoroda nebegalioja (galiojo 1 val.) – paprašyk naujos.'); end if;
  if p_pin is null then select name into nm from public.tracker_members where id = r.member_id; return jsonb_build_object('name', nm); end if;
  if p_pin !~ '^[0-9]{4,8}$' then return jsonb_build_object('error', 'PIN – 4–8 skaitmenys.'); end if;
  update public.tracker_members set pin_hash = crypt(p_pin, gen_salt('bf')), fails = 0, locked_until = null where id = r.member_id returning name into nm;
  update public.tracker_pin_resets set used_at = now() where member_id = r.member_id and used_at is null;
  delete from public.tracker_tokens where member_id = r.member_id;   -- every device signs in again with the new PIN
  return jsonb_build_object('ok', true, 'name', nm);
end $$;
revoke all on function public.tt_pin_reset(text, text) from public;
grant execute on function public.tt_pin_reset(text, text) to anon, authenticated;

revoke all on function public.tt_auth(uuid, text, text, boolean), public.tt_shift_json(uuid), public.tt_state_of(uuid), public.tt_manager() from public, anon, authenticated;
revoke all on function public.tt_members(), public.tt_register(text, text), public.tt_login(uuid, text), public.tt_logout(uuid, text),
  public.tt_state(uuid, text), public.tt_start(uuid, text, text), public.tt_switch(uuid, text, text), public.tt_stop(uuid, text, timestamptz),
  public.tt_report(uuid, text, timestamptz, timestamptz), public.tt_delete(uuid, text, text) from public, anon;
grant execute on function public.tt_members(), public.tt_register(text, text), public.tt_login(uuid, text), public.tt_logout(uuid, text),
  public.tt_state(uuid, text), public.tt_start(uuid, text, text), public.tt_switch(uuid, text, text), public.tt_stop(uuid, text, timestamptz),
  public.tt_report(uuid, text, timestamptz, timestamptz), public.tt_delete(uuid, text, text) to authenticated;

-- ---------- demo darbuotojas: 2 savaičių darbo dienos su atsitiktinėmis veiklomis ----------
do $$
declare mid uuid; d date; t timestamptz; sid uuid; k text; n int; i int; dur int; br boolean;
  kinds text[] := array['warehouse','driving','standby','setup','teardown','operator'];
begin
  if exists (select 1 from public.tracker_members where demo) then return; end if;
  insert into public.tracker_members (name, pin_hash, demo, created_by)
    values ('Demo darbuotojas', extensions.crypt('0000', extensions.gen_salt('bf')), true, null) returning id into mid;
  for d in select generate_series(current_date - 14, current_date - 1, interval '1 day')::date loop
    continue when extract(isodow from d) in (6, 7);
    t := (d + time '07:30' + make_interval(mins => (random() * 90)::int)) at time zone 'Europe/Vilnius';
    insert into public.time_shifts (member_id, started_at) values (mid, t) returning id into sid;
    n := 3 + (random() * 3)::int; br := false;
    for i in 1..n loop
      if not br and i > 1 and random() < 0.6 then
        k := 'break'; dur := 20 + (random() * 25)::int; br := true;
      else
        k := kinds[1 + (random() * 5)::int]; dur := 45 + (random() * 150)::int;
      end if;
      insert into public.time_entries (shift_id, kind, started_at, ended_at) values (sid, k, t, t + make_interval(mins => dur));
      t := t + make_interval(mins => dur);
    end loop;
    update public.time_shifts set ended_at = t where id = sid;
  end loop;
end $$;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';


-- ============================================================
-- „Team Tracker“: darbo laiko apskaita (kaip Connecteam „Time Clock“)
--  * tracker_members – Team Tracker nariai: vardas ir PIN kodas (PIN saugomas tik
--                      kaip maiša). Kiekvienas narys prisijungia atskirai savo PIN,
--                      tame pačiame telefone gali dirbti keli nariai.
--  * time_shifts     – pamaina: nuo „Pradėti darbą“ iki „Baigti darbą“
--  * time_entries    – pamainos dalys: sandėlis, vairavimas, budėjimas, montažas,
--                      demontažas, operatorius, pertrauka
--  * narys susietas su programėlės paskyra: viena paskyra – vienas narys (registruojasi vieną kartą)
--  * visiems matoma tik narių sąrašas (kiek užregistruota). Nario laiką mato pats narys
--    (savo paskyra arba prisijungęs jo PIN); Admin, Office ir Projektų vadovai – visų narių
--    (be PIN); Tech, Freelance, Runner – tik savo
--  * pamiršus PIN: į paskyros el. paštą siunčiama nuoroda (galioja 1 val.) – ją siunčia
--    funkcija push-notify (RESEND_API_KEY), PIN pakeičiamas per tt_pin_reset
--  * viskas tik per funkcijas tt_* (lentelių tiesiogiai neskaito niekas);
--    5 neteisingi PIN – 5 min. palaukti
--  * kas valandą priminimą „Team Tracker aktyvus“ siunčia push-notify (jau veikiantis
--    kas 5 min. darbas) – po šio failo iš naujo įdiek funkciją push-notify
--  * pridedamas „Demo darbuotojas“ (PIN 0000) su atsitiktinėmis 2 savaičių pamainomis
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.tracker_members (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  pin_hash      text not null,
  demo          boolean not null default false,
  fails         integer not null default 0,
  locked_until  timestamptz,
  created_by    uuid default auth.uid(),
  created_at    timestamptz not null default now()
);
create unique index if not exists tracker_members_name on public.tracker_members (lower(name));
alter table public.tracker_members add column if not exists user_id uuid references auth.users(id) on delete set null;
alter table public.tracker_members add column if not exists reset_sent_at timestamptz;
create unique index if not exists tracker_members_user on public.tracker_members (user_id) where user_id is not null;

-- „Pamiršau PIN“: vienkartinės nuorodos (galioja 1 val.)
create table if not exists public.tracker_pin_resets (
  token_hash  text primary key,
  member_id   uuid not null references public.tracker_members(id) on delete cascade,
  expires_at  timestamptz not null default now() + interval '1 hour',
  used_at     timestamptz,
  created_at  timestamptz not null default now()
);
alter table public.tracker_pin_resets enable row level security;
revoke all on public.tracker_pin_resets from anon, authenticated;

create table if not exists public.tracker_tokens (
  token_hash  text primary key,
  member_id   uuid not null references public.tracker_members(id) on delete cascade,
  user_id     uuid default auth.uid(),
  created_at  timestamptz not null default now()
);

create table if not exists public.time_shifts (
  id           uuid primary key default gen_random_uuid(),
  member_id    uuid not null references public.tracker_members(id) on delete cascade,
  started_by   uuid,                       -- the app account that pressed „Pradėti“ (gets the reminders)
  started_at   timestamptz not null default now(),
  ended_at     timestamptz,
  reminded_at  timestamptz,
  created_at   timestamptz not null default now()
);
create index if not exists time_shifts_member_time on public.time_shifts (member_id, started_at desc);
create unique index if not exists time_shifts_one_open on public.time_shifts (member_id) where ended_at is null;

create table if not exists public.time_entries (
  id          uuid primary key default gen_random_uuid(),
  shift_id    uuid not null references public.time_shifts(id) on delete cascade,
  kind        text not null check (kind in ('warehouse','driving','standby','setup','teardown','operator','break')),
  started_at  timestamptz not null default now(),
  ended_at    timestamptz
);
create index if not exists time_entries_shift on public.time_entries (shift_id, started_at);
create unique index if not exists time_entries_one_open on public.time_entries (shift_id) where ended_at is null;

alter table public.tracker_members enable row level security;
alter table public.tracker_tokens enable row level security;
alter table public.time_shifts enable row level security;
alter table public.time_entries enable row level security;
revoke all on public.tracker_members, public.tracker_tokens, public.time_shifts, public.time_entries from anon, authenticated;

-- ---------- pagalbinės ----------
-- who may see every member's time: Admin, Office, Projektų vadovas (Tech, Freelance, Runner – only their own)
create or replace function public.tt_manager() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','office','pm'), false)
$$;
-- PIN or the device's sign-in key (token); null = allowed. A manager / the member's own account may pass nothing (to look).
create or replace function public.tt_auth(m uuid, p_pin text, p_token text, admin_ok boolean) returns text
  language plpgsql security definer set search_path = public, extensions as $$
declare r public.tracker_members;
begin
  if auth.uid() is null or not public.is_approved() then return 'Reikia prisijungti prie programėlės.'; end if;
  select * into r from public.tracker_members where id = m;
  if r.id is null then return 'Tokio nario nėra.'; end if;
  if p_token is not null and exists (select 1 from public.tracker_tokens where member_id = m and token_hash = encode(digest(p_token, 'sha256'), 'hex')) then return null; end if;
  if p_pin is null then
    -- looking at the time (admin_ok): the member's own account, or Admin / Office / Projektų vadovas
    if admin_ok and (r.user_id = auth.uid() or public.tt_manager()) then return null; end if;
    return 'Prisijunk savo PIN kodu.';
  end if;
  if r.locked_until is not null and r.locked_until > now() then return 'Per daug neteisingų bandymų – palauk kelias minutes.'; end if;
  if r.pin_hash = crypt(p_pin, r.pin_hash) then
    update public.tracker_members set fails = 0, locked_until = null where id = m;
    return null;
  end if;
  update public.tracker_members set fails = case when fails >= 4 then 0 else fails + 1 end,
    locked_until = case when fails >= 4 then now() + interval '5 minutes' else locked_until end where id = m;
  return 'Neteisingas PIN kodas.';
end $$;

create or replace function public.tt_shift_json(sid uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', s.id, 'started_at', s.started_at, 'ended_at', s.ended_at,
    'entries', coalesce((select jsonb_agg(jsonb_build_object('kind', e.kind, 'started_at', e.started_at, 'ended_at', e.ended_at) order by e.started_at)
                         from public.time_entries e where e.shift_id = s.id), '[]'::jsonb))
  from public.time_shifts s where s.id = sid
$$;

create or replace function public.tt_state_of(m uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shift', (select public.tt_shift_json(id) from public.time_shifts where member_id = m and ended_at is null),
    'last', (select public.tt_shift_json(id) from public.time_shifts where member_id = m and ended_at is not null order by ended_at desc limit 1))
$$;

-- ---------- visiems: narių sąrašas (kiek užregistruota) ----------
create or replace function public.tt_members() returns jsonb
  language sql stable security definer set search_path = public as $$
  select case when public.is_approved() then coalesce((select jsonb_agg(jsonb_build_object('id', id, 'name', name, 'demo', demo, 'created_at', created_at, 'mine', user_id = auth.uid(), 'mail', user_id is not null) order by demo, lower(name)) from public.tracker_members), '[]'::jsonb) else '[]'::jsonb end
$$;

create or replace function public.tt_register(p_name text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare nm text := btrim(coalesce(p_name, '')); mid uuid; tok text;
begin
  if auth.uid() is null or not public.is_approved() then return jsonb_build_object('error', 'Reikia prisijungti prie programėlės.'); end if;
  if length(nm) < 2 or length(nm) > 60 then return jsonb_build_object('error', 'Įrašyk vardą ir pavardę.'); end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4,8}$' then return jsonb_build_object('error', 'PIN – 4–8 skaitmenys.'); end if;
  if exists (select 1 from public.tracker_members where user_id = auth.uid()) then return jsonb_build_object('error', 'Tu jau užregistruotas Team Tracker – prisijunk savo PIN (pamiršus – „Pamiršau PIN“).'); end if;
  if exists (select 1 from public.tracker_members where lower(name) = lower(nm)) then return jsonb_build_object('error', 'Toks narys jau užregistruotas.'); end if;
  insert into public.tracker_members (name, pin_hash, user_id) values (nm, crypt(p_pin, gen_salt('bf')), auth.uid()) returning id into mid;
  tok := encode(gen_random_bytes(24), 'hex');
  insert into public.tracker_tokens (token_hash, member_id) values (encode(digest(tok, 'sha256'), 'hex'), mid);
  return jsonb_build_object('token', tok, 'state', public.tt_state_of(mid));
end $$;

-- prisijungimas PIN kodu: šiam įrenginiui grąžinamas raktas (PIN neįsimenamas)
create or replace function public.tt_login(m uuid, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; tok text;
begin
  err := public.tt_auth(m, coalesce(p_pin, ''), null, false);
  if err is not null then return jsonb_build_object('error', err); end if;
  -- a member registered before accounts were linked: tied to the first account that signs in with the PIN
  update public.tracker_members set user_id = auth.uid()
   where id = m and user_id is null and not demo and not exists (select 1 from public.tracker_members where user_id = auth.uid());
  tok := encode(gen_random_bytes(24), 'hex');
  insert into public.tracker_tokens (token_hash, member_id) values (encode(digest(tok, 'sha256'), 'hex'), m);
  return jsonb_build_object('token', tok, 'state', public.tt_state_of(m));
end $$;

create or replace function public.tt_logout(m uuid, p_token text) returns void
  language sql security definer set search_path = public, extensions as $$
  delete from public.tracker_tokens where member_id = m and token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
$$;

create or replace function public.tt_state(m uuid, p_token text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return public.tt_state_of(m);
end $$;

-- „Pradėti darbą“
create or replace function public.tt_start(m uuid, p_token text, p_kind text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  if exists (select 1 from public.time_shifts where member_id = m and ended_at is null) then return public.tt_state_of(m); end if;
  insert into public.time_shifts (member_id, started_by) values (m, auth.uid()) returning id into sid;
  insert into public.time_entries (shift_id, kind) values (sid, p_kind);
  return public.tt_state_of(m);
end $$;

-- veiklos pakeitimas: ankstesnė užbaigiama ir išsaugoma, nauja pradedama dabar
create or replace function public.tt_switch(m uuid, p_token text, p_kind text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid; cur text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select id into sid from public.time_shifts where member_id = m and ended_at is null;
  if sid is null then return jsonb_build_object('error', 'Darbas nepradėtas.'); end if;
  select kind into cur from public.time_entries where shift_id = sid and ended_at is null;
  if cur is distinct from p_kind then
    update public.time_entries set ended_at = now() where shift_id = sid and ended_at is null;
    insert into public.time_entries (shift_id, kind) values (sid, p_kind);
  end if;
  return public.tt_state_of(m);
end $$;

-- „Baigti darbą“ (p_at – jei pamiršai baigti: ankstesnis laikas, bet ne ankstesnis už paskutinės veiklos pradžią)
create or replace function public.tt_stop(m uuid, p_token text, p_at timestamptz default null) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid; last_start timestamptz; t timestamptz;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select id into sid from public.time_shifts where member_id = m and ended_at is null;
  if sid is null then return public.tt_state_of(m); end if;
  select max(started_at) into last_start from public.time_entries where shift_id = sid;
  t := least(now(), greatest(coalesce(p_at, now()), coalesce(last_start, now())));
  update public.time_entries set ended_at = t where shift_id = sid and ended_at is null;
  update public.time_shifts set ended_at = t where id = sid;
  return public.tt_state_of(m);
end $$;

-- nario pamainos per laikotarpį (prisijungus; administratoriui – be PIN)
create or replace function public.tt_report(m uuid, p_token text, p_from timestamptz, p_to timestamptz) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, true);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shifts', coalesce((select jsonb_agg(public.tt_shift_json(s.id) order by s.started_at desc) from public.time_shifts s
       where s.member_id = m and s.started_at < p_to and coalesce(s.ended_at, now()) > p_from), '[]'::jsonb));
end $$;

-- nario ištrynimas su visu jo laiku: pats narys (savo paskyra / PIN / raktu) arba administratorius
create or replace function public.tt_delete(m uuid, p_token text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  if public.is_admin() or exists (select 1 from public.tracker_members where id = m and user_id = auth.uid()) then err := null;
  else err := public.tt_auth(m, p_pin, p_token, false); end if;
  if err is not null then return jsonb_build_object('error', err); end if;
  delete from public.tracker_members where id = m;
  return jsonb_build_object('ok', true);
end $$;

-- naujas PIN pagal nuorodą iš laiško (veikia ir neprisijungus prie programėlės; nuoroda vienkartinė, 1 val.)
create or replace function public.tt_pin_reset(p_token text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare r public.tracker_pin_resets; nm text;
begin
  select * into r from public.tracker_pin_resets where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  if r.token_hash is null or r.used_at is not null then return jsonb_build_object('error', 'Nuoroda neteisinga arba jau panaudota.'); end if;
  if r.expires_at < now() then return jsonb_build_object('error', 'Nuoroda nebegalioja (galiojo 1 val.) – paprašyk naujos.'); end if;
  if p_pin is null then select name into nm from public.tracker_members where id = r.member_id; return jsonb_build_object('name', nm); end if;
  if p_pin !~ '^[0-9]{4,8}$' then return jsonb_build_object('error', 'PIN – 4–8 skaitmenys.'); end if;
  update public.tracker_members set pin_hash = crypt(p_pin, gen_salt('bf')), fails = 0, locked_until = null where id = r.member_id returning name into nm;
  update public.tracker_pin_resets set used_at = now() where member_id = r.member_id and used_at is null;
  delete from public.tracker_tokens where member_id = r.member_id;   -- every device signs in again with the new PIN
  return jsonb_build_object('ok', true, 'name', nm);
end $$;
-- administratorius nustato nariui naują PIN (kai laiškas neateina ar narys be paskyros)
create or replace function public.tt_set_pin(m uuid, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.is_admin() then return jsonb_build_object('error', 'PIN keisti gali tik administratorius.'); end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4,8}$' then return jsonb_build_object('error', 'PIN – 4–8 skaitmenys.'); end if;
  update public.tracker_members set pin_hash = crypt(p_pin, gen_salt('bf')), fails = 0, locked_until = null where id = m and not demo;
  if not found then return jsonb_build_object('error', 'Tokio nario nėra.'); end if;
  delete from public.tracker_tokens where member_id = m;
  return jsonb_build_object('ok', true);
end $$;
revoke all on function public.tt_set_pin(uuid, text) from public, anon;
grant execute on function public.tt_set_pin(uuid, text) to authenticated;
revoke all on function public.tt_pin_reset(text, text) from public;
grant execute on function public.tt_pin_reset(text, text) to anon, authenticated;

revoke all on function public.tt_auth(uuid, text, text, boolean), public.tt_shift_json(uuid), public.tt_state_of(uuid), public.tt_manager() from public, anon, authenticated;
revoke all on function public.tt_members(), public.tt_register(text, text), public.tt_login(uuid, text), public.tt_logout(uuid, text),
  public.tt_state(uuid, text), public.tt_start(uuid, text, text), public.tt_switch(uuid, text, text), public.tt_stop(uuid, text, timestamptz),
  public.tt_report(uuid, text, timestamptz, timestamptz), public.tt_delete(uuid, text, text) from public, anon;
grant execute on function public.tt_members(), public.tt_register(text, text), public.tt_login(uuid, text), public.tt_logout(uuid, text),
  public.tt_state(uuid, text), public.tt_start(uuid, text, text), public.tt_switch(uuid, text, text), public.tt_stop(uuid, text, timestamptz),
  public.tt_report(uuid, text, timestamptz, timestamptz), public.tt_delete(uuid, text, text) to authenticated;

-- ---------- demo darbuotojas: 2 savaičių darbo dienos su atsitiktinėmis veiklomis ----------
do $$
declare mid uuid; d date; t timestamptz; sid uuid; k text; n int; i int; dur int; br boolean;
  kinds text[] := array['warehouse','driving','standby','setup','teardown','operator'];
begin
  if exists (select 1 from public.tracker_members where demo) then return; end if;
  insert into public.tracker_members (name, pin_hash, demo, created_by)
    values ('Demo darbuotojas', extensions.crypt('0000', extensions.gen_salt('bf')), true, null) returning id into mid;
  for d in select generate_series(current_date - 14, current_date - 1, interval '1 day')::date loop
    continue when extract(isodow from d) in (6, 7);
    t := (d + time '07:30' + make_interval(mins => (random() * 90)::int)) at time zone 'Europe/Vilnius';
    insert into public.time_shifts (member_id, started_at) values (mid, t) returning id into sid;
    n := 3 + (random() * 3)::int; br := false;
    for i in 1..n loop
      if not br and i > 1 and random() < 0.6 then
        k := 'break'; dur := 20 + (random() * 25)::int; br := true;
      else
        k := kinds[1 + (random() * 5)::int]; dur := 45 + (random() * 150)::int;
      end if;
      insert into public.time_entries (shift_id, kind, started_at, ended_at) values (sid, k, t, t + make_interval(mins => dur));
      t := t + make_interval(mins => dur);
    end loop;
    update public.time_shifts set ended_at = t where id = sid;
  end loop;
end $$;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';


-- ============================================================
-- „Team Tracker“: darbo laiko apskaita (kaip Connecteam „Time Clock“)
--  * tracker_members – Team Tracker nariai: vardas ir PIN kodas (PIN saugomas tik
--                      kaip maiša). Kiekvienas narys prisijungia atskirai savo PIN,
--                      tame pačiame telefone gali dirbti keli nariai.
--  * time_shifts     – pamaina: nuo „Pradėti darbą“ iki „Baigti darbą“
--  * time_entries    – pamainos dalys: sandėlis, vairavimas, budėjimas, montažas,
--                      demontažas, operatorius, pertrauka
--  * narys susietas su programėlės paskyra: viena paskyra – vienas narys (registruojasi vieną kartą)
--  * visiems matoma tik narių sąrašas (kiek užregistruota). Nario laiką mato pats narys
--    (savo paskyra arba prisijungęs jo PIN); Admin, Office ir Projektų vadovai – visų narių
--    (be PIN); Tech, Freelance, Runner – tik savo
--  * pamiršus PIN: į paskyros el. paštą siunčiama nuoroda (galioja 1 val.) – ją siunčia
--    funkcija push-notify (RESEND_API_KEY), PIN pakeičiamas per tt_pin_reset
--  * viskas tik per funkcijas tt_* (lentelių tiesiogiai neskaito niekas);
--    5 neteisingi PIN – 5 min. palaukti
--  * kas valandą priminimą „Team Tracker aktyvus“ siunčia push-notify (jau veikiantis
--    kas 5 min. darbas) – po šio failo iš naujo įdiek funkciją push-notify
--  * pridedamas „Demo darbuotojas“ (PIN 0000) su atsitiktinėmis 2 savaičių pamainomis
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.tracker_members (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  pin_hash      text not null,
  demo          boolean not null default false,
  fails         integer not null default 0,
  locked_until  timestamptz,
  created_by    uuid default auth.uid(),
  created_at    timestamptz not null default now()
);
create unique index if not exists tracker_members_name on public.tracker_members (lower(name));
alter table public.tracker_members add column if not exists user_id uuid references auth.users(id) on delete set null;
alter table public.tracker_members add column if not exists reset_sent_at timestamptz;
create unique index if not exists tracker_members_user on public.tracker_members (user_id) where user_id is not null;

-- „Pamiršau PIN“: vienkartinės nuorodos (galioja 1 val.)
create table if not exists public.tracker_pin_resets (
  token_hash  text primary key,
  member_id   uuid not null references public.tracker_members(id) on delete cascade,
  expires_at  timestamptz not null default now() + interval '1 hour',
  used_at     timestamptz,
  created_at  timestamptz not null default now()
);
alter table public.tracker_pin_resets enable row level security;
revoke all on public.tracker_pin_resets from anon, authenticated;

create table if not exists public.tracker_tokens (
  token_hash  text primary key,
  member_id   uuid not null references public.tracker_members(id) on delete cascade,
  user_id     uuid default auth.uid(),
  created_at  timestamptz not null default now()
);

create table if not exists public.time_shifts (
  id           uuid primary key default gen_random_uuid(),
  member_id    uuid not null references public.tracker_members(id) on delete cascade,
  started_by   uuid,                       -- the app account that pressed „Pradėti“ (gets the reminders)
  started_at   timestamptz not null default now(),
  ended_at     timestamptz,
  reminded_at  timestamptz,
  created_at   timestamptz not null default now()
);
create index if not exists time_shifts_member_time on public.time_shifts (member_id, started_at desc);
create unique index if not exists time_shifts_one_open on public.time_shifts (member_id) where ended_at is null;

create table if not exists public.time_entries (
  id          uuid primary key default gen_random_uuid(),
  shift_id    uuid not null references public.time_shifts(id) on delete cascade,
  kind        text not null check (kind in ('warehouse','driving','standby','setup','teardown','operator','break')),
  started_at  timestamptz not null default now(),
  ended_at    timestamptz
);
create index if not exists time_entries_shift on public.time_entries (shift_id, started_at);
create unique index if not exists time_entries_one_open on public.time_entries (shift_id) where ended_at is null;

alter table public.tracker_members enable row level security;
alter table public.tracker_tokens enable row level security;
alter table public.time_shifts enable row level security;
alter table public.time_entries enable row level security;
revoke all on public.tracker_members, public.tracker_tokens, public.time_shifts, public.time_entries from anon, authenticated;

-- ---------- pagalbinės ----------
-- who may see every member's time: Admin, Office, Projektų vadovas (Tech, Freelance, Runner – only their own)
create or replace function public.tt_manager() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','office','pm'), false)
$$;
-- PIN or the device's sign-in key (token); null = allowed. A manager / the member's own account may pass nothing (to look).
create or replace function public.tt_auth(m uuid, p_pin text, p_token text, admin_ok boolean) returns text
  language plpgsql security definer set search_path = public, extensions as $$
declare r public.tracker_members;
begin
  if auth.uid() is null or not public.is_approved() then return 'Reikia prisijungti prie programėlės.'; end if;
  select * into r from public.tracker_members where id = m;
  if r.id is null then return 'Tokio nario nėra.'; end if;
  if p_token is not null and exists (select 1 from public.tracker_tokens where member_id = m and token_hash = encode(digest(p_token, 'sha256'), 'hex')) then return null; end if;
  if p_pin is null then
    -- looking at the time (admin_ok): the member's own account, or Admin / Office / Projektų vadovas
    if admin_ok and (r.user_id = auth.uid() or public.tt_manager()) then return null; end if;
    return 'Prisijunk savo PIN kodu.';
  end if;
  if r.locked_until is not null and r.locked_until > now() then return 'Per daug neteisingų bandymų – palauk kelias minutes.'; end if;
  if r.pin_hash = crypt(p_pin, r.pin_hash) then
    update public.tracker_members set fails = 0, locked_until = null where id = m;
    return null;
  end if;
  update public.tracker_members set fails = case when fails >= 4 then 0 else fails + 1 end,
    locked_until = case when fails >= 4 then now() + interval '5 minutes' else locked_until end where id = m;
  return 'Neteisingas PIN kodas.';
end $$;

create or replace function public.tt_shift_json(sid uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', s.id, 'started_at', s.started_at, 'ended_at', s.ended_at,
    'entries', coalesce((select jsonb_agg(jsonb_build_object('kind', e.kind, 'started_at', e.started_at, 'ended_at', e.ended_at) order by e.started_at)
                         from public.time_entries e where e.shift_id = s.id), '[]'::jsonb))
  from public.time_shifts s where s.id = sid
$$;

create or replace function public.tt_state_of(m uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shift', (select public.tt_shift_json(id) from public.time_shifts where member_id = m and ended_at is null),
    'last', (select public.tt_shift_json(id) from public.time_shifts where member_id = m and ended_at is not null order by ended_at desc limit 1))
$$;

-- ---------- visiems: narių sąrašas (kiek užregistruota) ----------
create or replace function public.tt_members() returns jsonb
  language sql stable security definer set search_path = public as $$
  select case when public.is_approved() then coalesce((select jsonb_agg(jsonb_build_object('id', id, 'name', name, 'demo', demo, 'created_at', created_at, 'mine', user_id = auth.uid(), 'mail', user_id is not null) order by demo, lower(name)) from public.tracker_members), '[]'::jsonb) else '[]'::jsonb end
$$;

create or replace function public.tt_register(p_name text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare nm text := btrim(coalesce(p_name, '')); mid uuid; tok text;
begin
  if auth.uid() is null or not public.is_approved() then return jsonb_build_object('error', 'Reikia prisijungti prie programėlės.'); end if;
  if length(nm) < 2 or length(nm) > 60 then return jsonb_build_object('error', 'Įrašyk vardą ir pavardę.'); end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4,8}$' then return jsonb_build_object('error', 'PIN – 4–8 skaitmenys.'); end if;
  if exists (select 1 from public.tracker_members where user_id = auth.uid()) then return jsonb_build_object('error', 'Tu jau užregistruotas Team Tracker – prisijunk savo PIN (pamiršus – „Pamiršau PIN“).'); end if;
  if exists (select 1 from public.tracker_members where lower(name) = lower(nm)) then return jsonb_build_object('error', 'Toks narys jau užregistruotas.'); end if;
  insert into public.tracker_members (name, pin_hash, user_id) values (nm, crypt(p_pin, gen_salt('bf')), auth.uid()) returning id into mid;
  tok := encode(gen_random_bytes(24), 'hex');
  insert into public.tracker_tokens (token_hash, member_id) values (encode(digest(tok, 'sha256'), 'hex'), mid);
  return jsonb_build_object('token', tok, 'state', public.tt_state_of(mid));
end $$;

-- prisijungimas PIN kodu: šiam įrenginiui grąžinamas raktas (PIN neįsimenamas)
create or replace function public.tt_login(m uuid, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; tok text;
begin
  err := public.tt_auth(m, coalesce(p_pin, ''), null, false);
  if err is not null then return jsonb_build_object('error', err); end if;
  -- a member registered before accounts were linked: tied to the first account that signs in with the PIN
  update public.tracker_members set user_id = auth.uid()
   where id = m and user_id is null and not demo and not exists (select 1 from public.tracker_members where user_id = auth.uid());
  tok := encode(gen_random_bytes(24), 'hex');
  insert into public.tracker_tokens (token_hash, member_id) values (encode(digest(tok, 'sha256'), 'hex'), m);
  return jsonb_build_object('token', tok, 'state', public.tt_state_of(m));
end $$;

create or replace function public.tt_logout(m uuid, p_token text) returns void
  language sql security definer set search_path = public, extensions as $$
  delete from public.tracker_tokens where member_id = m and token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
$$;

create or replace function public.tt_state(m uuid, p_token text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return public.tt_state_of(m);
end $$;

-- „Pradėti darbą“
create or replace function public.tt_start(m uuid, p_token text, p_kind text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  if exists (select 1 from public.time_shifts where member_id = m and ended_at is null) then return public.tt_state_of(m); end if;
  insert into public.time_shifts (member_id, started_by) values (m, auth.uid()) returning id into sid;
  insert into public.time_entries (shift_id, kind) values (sid, p_kind);
  return public.tt_state_of(m);
end $$;

-- veiklos pakeitimas: ankstesnė užbaigiama ir išsaugoma, nauja pradedama dabar
create or replace function public.tt_switch(m uuid, p_token text, p_kind text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid; cur text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select id into sid from public.time_shifts where member_id = m and ended_at is null;
  if sid is null then return jsonb_build_object('error', 'Darbas nepradėtas.'); end if;
  select kind into cur from public.time_entries where shift_id = sid and ended_at is null;
  if cur is distinct from p_kind then
    update public.time_entries set ended_at = now() where shift_id = sid and ended_at is null;
    insert into public.time_entries (shift_id, kind) values (sid, p_kind);
  end if;
  return public.tt_state_of(m);
end $$;

-- „Baigti darbą“ (p_at – jei pamiršai baigti: ankstesnis laikas, bet ne ankstesnis už paskutinės veiklos pradžią)
create or replace function public.tt_stop(m uuid, p_token text, p_at timestamptz default null) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid; last_start timestamptz; t timestamptz;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select id into sid from public.time_shifts where member_id = m and ended_at is null;
  if sid is null then return public.tt_state_of(m); end if;
  select max(started_at) into last_start from public.time_entries where shift_id = sid;
  t := least(now(), greatest(coalesce(p_at, now()), coalesce(last_start, now())));
  update public.time_entries set ended_at = t where shift_id = sid and ended_at is null;
  update public.time_shifts set ended_at = t where id = sid;
  return public.tt_state_of(m);
end $$;

-- nario pamainos per laikotarpį (prisijungus; administratoriui – be PIN)
create or replace function public.tt_report(m uuid, p_token text, p_from timestamptz, p_to timestamptz) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, true);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shifts', coalesce((select jsonb_agg(public.tt_shift_json(s.id) order by s.started_at desc) from public.time_shifts s
       where s.member_id = m and s.started_at < p_to and coalesce(s.ended_at, now()) > p_from), '[]'::jsonb));
end $$;

-- nario ištrynimas su visu jo laiku: pats narys (savo paskyra / PIN / raktu) arba administratorius
create or replace function public.tt_delete(m uuid, p_token text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  if public.is_admin() or exists (select 1 from public.tracker_members where id = m and user_id = auth.uid()) then err := null;
  else err := public.tt_auth(m, p_pin, p_token, false); end if;
  if err is not null then return jsonb_build_object('error', err); end if;
  delete from public.tracker_members where id = m;
  return jsonb_build_object('ok', true);
end $$;

-- naujas PIN pagal nuorodą iš laiško (veikia ir neprisijungus prie programėlės; nuoroda vienkartinė, 1 val.)
create or replace function public.tt_pin_reset(p_token text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare r public.tracker_pin_resets; nm text;
begin
  select * into r from public.tracker_pin_resets where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  if r.token_hash is null or r.used_at is not null then return jsonb_build_object('error', 'Nuoroda neteisinga arba jau panaudota.'); end if;
  if r.expires_at < now() then return jsonb_build_object('error', 'Nuoroda nebegalioja (galiojo 1 val.) – paprašyk naujos.'); end if;
  if p_pin is null then select name into nm from public.tracker_members where id = r.member_id; return jsonb_build_object('name', nm); end if;
  if p_pin !~ '^[0-9]{4,8}$' then return jsonb_build_object('error', 'PIN – 4–8 skaitmenys.'); end if;
  update public.tracker_members set pin_hash = crypt(p_pin, gen_salt('bf')), fails = 0, locked_until = null where id = r.member_id returning name into nm;
  update public.tracker_pin_resets set used_at = now() where member_id = r.member_id and used_at is null;
  delete from public.tracker_tokens where member_id = r.member_id;   -- every device signs in again with the new PIN
  return jsonb_build_object('ok', true, 'name', nm);
end $$;
-- narys, užregistruotas prieš susiejimą su paskyromis, susiejamas su paskyra, kurios vardas ir pavardė sutampa
-- (tik jei ta paskyra dar neturi nario ir toks narys vienas)
create or replace function public.tt_claim() returns jsonb
  language plpgsql security definer set search_path = public as $$
declare nm text; mid uuid; n int;
begin
  if auth.uid() is null or not public.is_approved() then return jsonb_build_object('linked', false); end if;
  if exists (select 1 from public.tracker_members where user_id = auth.uid()) then return jsonb_build_object('linked', false); end if;
  select lower(btrim(coalesce(first_name,'')||' '||coalesce(last_name,''))) into nm from public.profiles where id = auth.uid();
  if coalesce(nm, '') = '' then return jsonb_build_object('linked', false); end if;
  select count(*), min(id::text)::uuid into n, mid from public.tracker_members where user_id is null and not demo and lower(btrim(name)) = nm;
  if n <> 1 then return jsonb_build_object('linked', false); end if;
  update public.tracker_members set user_id = auth.uid() where id = mid and user_id is null;
  return jsonb_build_object('linked', true, 'id', mid);
end $$;
revoke all on function public.tt_claim() from public, anon;
grant execute on function public.tt_claim() to authenticated;

-- administratorius nustato nariui naują PIN (kai laiškas neateina ar narys be paskyros)
create or replace function public.tt_set_pin(m uuid, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.is_admin() then return jsonb_build_object('error', 'PIN keisti gali tik administratorius.'); end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4,8}$' then return jsonb_build_object('error', 'PIN – 4–8 skaitmenys.'); end if;
  update public.tracker_members set pin_hash = crypt(p_pin, gen_salt('bf')), fails = 0, locked_until = null where id = m and not demo;
  if not found then return jsonb_build_object('error', 'Tokio nario nėra.'); end if;
  delete from public.tracker_tokens where member_id = m;
  return jsonb_build_object('ok', true);
end $$;
revoke all on function public.tt_set_pin(uuid, text) from public, anon;
grant execute on function public.tt_set_pin(uuid, text) to authenticated;
revoke all on function public.tt_pin_reset(text, text) from public;
grant execute on function public.tt_pin_reset(text, text) to anon, authenticated;

revoke all on function public.tt_auth(uuid, text, text, boolean), public.tt_shift_json(uuid), public.tt_state_of(uuid), public.tt_manager() from public, anon, authenticated;
revoke all on function public.tt_members(), public.tt_register(text, text), public.tt_login(uuid, text), public.tt_logout(uuid, text),
  public.tt_state(uuid, text), public.tt_start(uuid, text, text), public.tt_switch(uuid, text, text), public.tt_stop(uuid, text, timestamptz),
  public.tt_report(uuid, text, timestamptz, timestamptz), public.tt_delete(uuid, text, text) from public, anon;
grant execute on function public.tt_members(), public.tt_register(text, text), public.tt_login(uuid, text), public.tt_logout(uuid, text),
  public.tt_state(uuid, text), public.tt_start(uuid, text, text), public.tt_switch(uuid, text, text), public.tt_stop(uuid, text, timestamptz),
  public.tt_report(uuid, text, timestamptz, timestamptz), public.tt_delete(uuid, text, text) to authenticated;

-- ---------- demo darbuotojas: 2 savaičių darbo dienos su atsitiktinėmis veiklomis ----------
do $$
declare mid uuid; d date; t timestamptz; sid uuid; k text; n int; i int; dur int; br boolean;
  kinds text[] := array['warehouse','driving','standby','setup','teardown','operator'];
begin
  if exists (select 1 from public.tracker_members where demo) then return; end if;
  insert into public.tracker_members (name, pin_hash, demo, created_by)
    values ('Demo darbuotojas', extensions.crypt('0000', extensions.gen_salt('bf')), true, null) returning id into mid;
  for d in select generate_series(current_date - 14, current_date - 1, interval '1 day')::date loop
    continue when extract(isodow from d) in (6, 7);
    t := (d + time '07:30' + make_interval(mins => (random() * 90)::int)) at time zone 'Europe/Vilnius';
    insert into public.time_shifts (member_id, started_at) values (mid, t) returning id into sid;
    n := 3 + (random() * 3)::int; br := false;
    for i in 1..n loop
      if not br and i > 1 and random() < 0.6 then
        k := 'break'; dur := 20 + (random() * 25)::int; br := true;
      else
        k := kinds[1 + (random() * 5)::int]; dur := 45 + (random() * 150)::int;
      end if;
      insert into public.time_entries (shift_id, kind, started_at, ended_at) values (sid, k, t, t + make_interval(mins => dur));
      t := t + make_interval(mins => dur);
    end loop;
    update public.time_shifts set ended_at = t where id = sid;
  end loop;
end $$;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';


-- ============================================================
-- „Pirkiniai“: pirkinių skiltys (kaip Excel lapai: VIDEO, LIGHT, AUDIO, Bendri daiktai…)
--  * viena eilutė = viena skiltis; jos lentelė (eilutės, langeliai, formulės) – rows (jsonb)
--  * vieša (visible = 'public') – mato visi, kam leista „Pirkiniai“, keisti gali kas juos redaguoja;
--    tik man (visible = 'private') – mato ir keičia tik sukūręs
--  * viešumą ir pavadinimą keičia tik savininkas (ar administratorius)
--  * „Pasiūlymai“ (purchase_proposals): kiekvienas narys pasiūlo, ką pirkti – mato visi;
--    sąrašus (purchase_lists) mato ir tvarko tik Admin, Office ir Projektų vadovai – jie
--    pasiūlymą priima (įkelia į sąrašą) arba atmeta
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- skiltis „Pirkiniai“ teisių lentelėje ----------
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people','newproj','invoices','buy'));
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','buy',true,true), ('office','buy',true,true), ('tech','buy',true,true),
  ('freelance','buy',false,false), ('runner','buy',false,false)
on conflict (role, section) do nothing;

create table if not exists public.purchase_lists (
  id               uuid primary key default gen_random_uuid(),
  name             text not null default 'Nauja skiltis',
  visible          text not null default 'public' check (visible in ('public','private')),
  owner            uuid not null default auth.uid() references auth.users(id) on delete cascade,
  owner_name       text,
  sort             integer not null default 0,
  cols             jsonb not null default '[]'::jsonb,   -- column titles (A…H)
  rows             jsonb not null default '[]'::jsonb,   -- [{id, sec?, c:{A:'…', B:'=…'}}]
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  updated_by       uuid,
  updated_by_name  text
);
create index if not exists purchase_lists_sort on public.purchase_lists (sort, created_at);

create or replace function public.purchase_lists_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'UPDATE' and old.owner <> auth.uid() and not public.is_admin() then
    if new.owner <> old.owner or new.visible <> old.visible or new.name <> old.name then
      raise exception 'Pavadinimą ir matomumą keičia tik skilties savininkas.';
    end if;
  end if;
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end $$;
drop trigger if exists purchase_lists_guard on public.purchase_lists;
create trigger purchase_lists_guard before insert or update on public.purchase_lists
  for each row execute function public.purchase_lists_guard();

-- who keeps the lists: Admin, Office, Projektų vadovai
create or replace function public.buy_manager() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','office','pm'), false)
$$;
grant execute on function public.buy_manager() to authenticated;

alter table public.purchase_lists enable row level security;
drop policy if exists "purchase lists view" on public.purchase_lists;
create policy "purchase lists view" on public.purchase_lists for select to authenticated
  using (owner = auth.uid() or (visible = 'public' and public.buy_manager()));
drop policy if exists "purchase lists add" on public.purchase_lists;
create policy "purchase lists add" on public.purchase_lists for insert to authenticated
  with check (owner = auth.uid() and public.buy_manager());
drop policy if exists "purchase lists change" on public.purchase_lists;
create policy "purchase lists change" on public.purchase_lists for update to authenticated
  using (owner = auth.uid() or (visible = 'public' and public.buy_manager()))
  with check (owner = auth.uid() or (visible = 'public' and public.buy_manager()));
drop policy if exists "purchase lists delete" on public.purchase_lists;
create policy "purchase lists delete" on public.purchase_lists for delete to authenticated
  using (owner = auth.uid() or public.is_admin());
revoke all on public.purchase_lists from anon;
grant select, insert, update, delete on public.purchase_lists to authenticated;

-- ---------- Pasiūlymai ----------
create table if not exists public.purchase_proposals (
  id               uuid primary key default gen_random_uuid(),
  name             text not null,
  qty              numeric,
  price            numeric,
  link             text,
  category         text,
  prio             integer not null default 2,
  note             text,
  status           text not null default 'new' check (status in ('new','accepted','rejected')),
  list_id          uuid references public.purchase_lists(id) on delete set null,
  list_name        text,
  decision_note    text,
  decided_by_name  text,
  decided_at       timestamptz,
  created_by       uuid not null default auth.uid() references auth.users(id) on delete cascade,
  created_by_name  text,
  created_at       timestamptz not null default now()
);
create index if not exists purchase_proposals_time on public.purchase_proposals (created_at desc);
alter table public.purchase_proposals enable row level security;
drop policy if exists "proposals view" on public.purchase_proposals;
create policy "proposals view" on public.purchase_proposals for select to authenticated using (public.is_approved());
drop policy if exists "proposals add" on public.purchase_proposals;
create policy "proposals add" on public.purchase_proposals for insert to authenticated
  with check (public.is_approved() and created_by = auth.uid() and status = 'new');
drop policy if exists "proposals change" on public.purchase_proposals;
create policy "proposals change" on public.purchase_proposals for update to authenticated
  using (public.buy_manager() or (created_by = auth.uid() and status = 'new'))
  with check (public.buy_manager() or (created_by = auth.uid() and status = 'new'));
drop policy if exists "proposals delete" on public.purchase_proposals;
create policy "proposals delete" on public.purchase_proposals for delete to authenticated
  using (public.is_admin() or (created_by = auth.uid() and status = 'new'));
revoke all on public.purchase_proposals from anon;
grant select, insert, update, delete on public.purchase_proposals to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';


-- ============================================================
-- Pradžios puslapio kortelė „Pranešimai“: kiekvieno nario pranešimai (žinutės,
-- paminėjimai, kalendorius, renginiai, užduotys, sąskaitos, įranga, prašymai…).
--  * įrašo funkcija push-notify – tą patį, ką siunčia į telefoną (net jei pranešimai
--    telefone išjungti); tas pats pranešimas (tag) tik atnaujinamas
--  * kiekvienas mato ir žymi perskaitytais tik savo; senesni nei 30 d. ištrinami
-- Po šio failo iš naujo įdiek funkciją push-notify.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.user_notifications (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users(id) on delete cascade,
  tag         text not null,
  kind        text,
  title       text not null default '',
  body        text not null default '',
  url         text not null default './',
  created_at  timestamptz not null default now(),
  read_at     timestamptz
);
create unique index if not exists user_notifications_tag on public.user_notifications (user_id, tag);
create index if not exists user_notifications_time on public.user_notifications (user_id, created_at desc);

alter table public.user_notifications enable row level security;
drop policy if exists "own notifications" on public.user_notifications;
create policy "own notifications" on public.user_notifications for select to authenticated using (user_id = auth.uid());
drop policy if exists "read own notifications" on public.user_notifications;
create policy "read own notifications" on public.user_notifications for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
drop policy if exists "remove own notifications" on public.user_notifications;
create policy "remove own notifications" on public.user_notifications for delete to authenticated using (user_id = auth.uid());
revoke all on public.user_notifications from anon;
grant select, update, delete on public.user_notifications to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';


-- ============================================================
-- „Pirkiniai“: pirkinių skiltys (kaip Excel lapai: VIDEO, LIGHT, AUDIO, Bendri daiktai…)
--  * viena eilutė = viena skiltis; jos lentelė (eilutės, langeliai, formulės) – rows (jsonb)
--  * vieša (visible = 'public') – mato visi, kam leista „Pirkiniai“, keisti gali kas juos redaguoja;
--    tik man (visible = 'private') – mato ir keičia tik sukūręs
--  * viešumą ir pavadinimą keičia tik savininkas (ar administratorius)
--  * „Pasiūlymai“ (purchase_proposals): kiekvienas narys pasiūlo, ką pirkti – mato visi;
--    sąrašus (purchase_lists) mato ir tvarko tik Admin, Office ir Projektų vadovai (net savo
--    sukurtų sąrašų narys su kitu lygiu nemato) – jie
--    pasiūlymą priima (įkelia į sąrašą) arba atmeta
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- skiltis „Pirkiniai“ teisių lentelėje ----------
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people','newproj','invoices','buy'));
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','buy',true,true), ('office','buy',true,true), ('tech','buy',true,true),
  ('freelance','buy',false,false), ('runner','buy',false,false)
on conflict (role, section) do nothing;

create table if not exists public.purchase_lists (
  id               uuid primary key default gen_random_uuid(),
  name             text not null default 'Nauja skiltis',
  visible          text not null default 'public' check (visible in ('public','private')),
  owner            uuid not null default auth.uid() references auth.users(id) on delete cascade,
  owner_name       text,
  sort             integer not null default 0,
  cols             jsonb not null default '[]'::jsonb,   -- column titles (A…H)
  rows             jsonb not null default '[]'::jsonb,   -- [{id, sec?, c:{A:'…', B:'=…'}}]
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  updated_by       uuid,
  updated_by_name  text
);
create index if not exists purchase_lists_sort on public.purchase_lists (sort, created_at);

create or replace function public.purchase_lists_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'UPDATE' and old.owner <> auth.uid() and not public.is_admin() then
    if new.owner <> old.owner or new.visible <> old.visible or new.name <> old.name then
      raise exception 'Pavadinimą ir matomumą keičia tik skilties savininkas.';
    end if;
  end if;
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end $$;
drop trigger if exists purchase_lists_guard on public.purchase_lists;
create trigger purchase_lists_guard before insert or update on public.purchase_lists
  for each row execute function public.purchase_lists_guard();

-- who keeps the lists: Admin, Office, Projektų vadovai
create or replace function public.buy_manager() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','office','pm'), false)
$$;
grant execute on function public.buy_manager() to authenticated;

alter table public.purchase_lists enable row level security;
drop policy if exists "purchase lists view" on public.purchase_lists;
create policy "purchase lists view" on public.purchase_lists for select to authenticated
  using (public.buy_manager() and (owner = auth.uid() or visible = 'public'));
drop policy if exists "purchase lists add" on public.purchase_lists;
create policy "purchase lists add" on public.purchase_lists for insert to authenticated
  with check (owner = auth.uid() and public.buy_manager());
drop policy if exists "purchase lists change" on public.purchase_lists;
create policy "purchase lists change" on public.purchase_lists for update to authenticated
  using (public.buy_manager() and (owner = auth.uid() or visible = 'public'))
  with check (public.buy_manager() and (owner = auth.uid() or visible = 'public'));
drop policy if exists "purchase lists delete" on public.purchase_lists;
create policy "purchase lists delete" on public.purchase_lists for delete to authenticated
  using (public.buy_manager() and (owner = auth.uid() or public.is_admin()));
revoke all on public.purchase_lists from anon;
grant select, insert, update, delete on public.purchase_lists to authenticated;

-- ---------- Pasiūlymai ----------
create table if not exists public.purchase_proposals (
  id               uuid primary key default gen_random_uuid(),
  name             text not null,
  qty              numeric,
  price            numeric,
  link             text,
  category         text,
  prio             integer not null default 2,
  note             text,
  status           text not null default 'new' check (status in ('new','accepted','rejected')),
  list_id          uuid references public.purchase_lists(id) on delete set null,
  list_name        text,
  decision_note    text,
  decided_by_name  text,
  decided_at       timestamptz,
  created_by       uuid not null default auth.uid() references auth.users(id) on delete cascade,
  created_by_name  text,
  created_at       timestamptz not null default now()
);
create index if not exists purchase_proposals_time on public.purchase_proposals (created_at desc);
alter table public.purchase_proposals enable row level security;
drop policy if exists "proposals view" on public.purchase_proposals;
create policy "proposals view" on public.purchase_proposals for select to authenticated using (public.is_approved());
drop policy if exists "proposals add" on public.purchase_proposals;
create policy "proposals add" on public.purchase_proposals for insert to authenticated
  with check (public.is_approved() and created_by = auth.uid() and status = 'new');
drop policy if exists "proposals change" on public.purchase_proposals;
create policy "proposals change" on public.purchase_proposals for update to authenticated
  using (public.buy_manager() or (created_by = auth.uid() and status = 'new'))
  with check (public.buy_manager() or (created_by = auth.uid() and status = 'new'));
drop policy if exists "proposals delete" on public.purchase_proposals;
create policy "proposals delete" on public.purchase_proposals for delete to authenticated
  using (public.is_admin() or (created_by = auth.uid() and status = 'new'));
revoke all on public.purchase_proposals from anon;
grant select, insert, update, delete on public.purchase_proposals to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';


-- ============================================================
-- Tech lygis nemato „Ataskaitos“ (Admin skiltyje teises galima pakeisti bet kada).
-- Transporte Tech mato tik automobilius (Transporto nuoma ir UTA kortelės – tik
-- Admin, Office ir Projektų vadovams) – tai nustato programėlė.
-- Supabase → SQL Editor → New query → įklijuok → Run. Saugu paleisti pakartotinai.
-- ============================================================
insert into public.role_permissions (role, section, can_view, can_edit) values ('tech','stats',false,false)
on conflict (role, section) do update set can_view = false, can_edit = false;


-- ============================================================
-- Tech lygis nemato „Ataskaitos“; Runner gali įkelti savo sąskaitas ir matyti tik savo įkeltas
-- (Admin skiltyje teises galima pakeisti bet kada).
-- Transporte Tech mato tik automobilius (Transporto nuoma ir UTA kortelės – tik
-- Admin, Office ir Projektų vadovams) – tai nustato programėlė.
-- Supabase → SQL Editor → New query → įklijuok → Run. Saugu paleisti pakartotinai.
-- ============================================================
insert into public.role_permissions (role, section, can_view, can_edit) values ('tech','stats',false,false)
on conflict (role, section) do update set can_view = false, can_edit = false;
insert into public.role_permissions (role, section, can_view, can_edit) values ('runner','invoices',true,true)
on conflict (role, section) do update set can_view = true, can_edit = true;


-- ============================================================
-- Sąskaitos: įkelti savo sąskaitą gali kiekvienas, kas mato „Sąskaitas“
-- (Tech, Freelance, Runner ir kt.), ir mato tik savo įkeltas bei jų būsenas.
-- Tvirtinti ir matyti visas – kaip anksčiau, tik Admin+.
-- Supabase → SQL Editor → New query → įklijuok → Run. Saugu paleisti pakartotinai.
-- ============================================================
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('tech','invoices',true,true), ('freelance','invoices',true,true), ('runner','invoices',true,true)
on conflict (role, section) do update set can_view = true, can_edit = true;

drop policy if exists "invoices add" on public.invoices;
create policy "invoices add" on public.invoices
  for insert to authenticated with check (
    created_by = auth.uid() and public.can_view('invoices')
    and status = 'new' and decision_by is null and decision_at is null and sent = '[]'::jsonb and responses = '[]'::jsonb
  );
drop policy if exists "invoice files add" on storage.objects;
create policy "invoice files add" on storage.objects
  for insert to authenticated with check (bucket_id = 'invoice-files' and (storage.foldername(name))[1] = auth.uid()::text and public.can_view('invoices'));


-- ============================================================
-- Tech lygis nemato „Ataskaitos“; Runner gali įkelti savo sąskaitas ir matyti tik savo įkeltas
-- Transporte Tech, Freelance ir Runner tik žiūri automobilius ir jų dokumentus (tech. apžiūra, kelių mokestis…), nieko neprideda ir nekeičia.
-- (Admin skiltyje teises galima pakeisti bet kada).
-- Transporte Tech mato tik automobilius (Transporto nuoma ir UTA kortelės – tik
-- Admin, Office ir Projektų vadovams) – tai nustato programėlė.
-- Supabase → SQL Editor → New query → įklijuok → Run. Saugu paleisti pakartotinai.
-- ============================================================
insert into public.role_permissions (role, section, can_view, can_edit) values ('tech','stats',false,false)
on conflict (role, section) do update set can_view = false, can_edit = false;
insert into public.role_permissions (role, section, can_view, can_edit) values ('runner','invoices',true,true)
on conflict (role, section) do update set can_view = true, can_edit = true;
insert into public.role_permissions (role, section, can_view, can_edit) values ('tech','fleet',true,false), ('freelance','fleet',true,false), ('runner','fleet',true,false)
on conflict (role, section) do update set can_view = true, can_edit = false;


-- ============================================================
-- „Išlaidos“: kuro, maisto ir kitos nario išlaidos su kvitais
--  * expenses      – kiekviena išlaida (kas, kada, kam, kiek, UTA ar savi pinigai, kvitai);
--                    mėnesio gale Admin / Office / Projektų vadovas patvirtina ir priskiria kompensaciją
--  * uta_personal  – UTA kortelės pylimai, pažymėti kaip asmeniniai (iš sukauptos kompensacijos)
--  * expense-files – kvitų nuotraukos / failai (<nario id>/<išlaidos id>/<failas>)
-- Narys mato ir rašo savo; Admin / Office / Projektų vadovas – visų.
-- Narys taip pat mato savo (jam priskirtos) UTA kortelės pylimus.
-- Reikia: purchases.sql (buy_manager) ir uta.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.expenses (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null default auth.uid() references auth.users(id) on delete cascade,
  user_name     text,
  kind          text not null check (kind in ('fuel','food','other')),
  spent_on      date not null,
  route         text not null default '',
  reason        text not null default '',
  liters        numeric(10,2),
  amount        numeric(12,2),
  paid          text not null default 'own' check (paid in ('uta','own')),
  uta_tx_id     uuid references public.uta_tx(id) on delete set null,
  receipts      jsonb not null default '[]'::jsonb,
  status        text not null default 'new' check (status in ('new','ok','rejected')),
  comp          numeric(12,2),
  review_note   text,
  reviewed_by   uuid,
  reviewed_name text,
  reviewed_at   timestamptz,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create index if not exists expenses_user_date on public.expenses (user_id, spent_on);
create index if not exists expenses_date on public.expenses (spent_on);

create table if not exists public.uta_personal (
  tx_id      uuid primary key references public.uta_tx(id) on delete cascade,
  user_id    uuid not null references auth.users(id) on delete cascade,
  marked_by  uuid default auth.uid(),
  created_at timestamptz not null default now()
);

-- the fill is on a UTA card given to this member
create or replace function public.uta_tx_mine(tx uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.uta_tx t join public.uta_cards c on c.id = t.card_id
                 where t.id = tx and c.assign_kind = 'person' and c.person_id = auth.uid())
$$;
grant execute on function public.uta_tx_mine(uuid) to authenticated;

alter table public.expenses enable row level security;
alter table public.uta_personal enable row level security;

drop policy if exists "expenses view" on public.expenses;
create policy "expenses view" on public.expenses for select to authenticated
  using (user_id = auth.uid() or public.buy_manager());
drop policy if exists "expenses add" on public.expenses;
create policy "expenses add" on public.expenses for insert to authenticated
  with check (user_id = auth.uid() and public.is_approved() and status = 'new' and comp is null);
-- the member changes / removes own ones until they are checked; the managers always
drop policy if exists "expenses edit" on public.expenses;
create policy "expenses edit" on public.expenses for update to authenticated
  using (public.buy_manager() or (user_id = auth.uid() and status = 'new'))
  with check (public.buy_manager() or (user_id = auth.uid() and status = 'new' and comp is null));
drop policy if exists "expenses remove" on public.expenses;
create policy "expenses remove" on public.expenses for delete to authenticated
  using (public.buy_manager() or (user_id = auth.uid() and status = 'new'));

drop policy if exists "uta personal view" on public.uta_personal;
create policy "uta personal view" on public.uta_personal for select to authenticated
  using (user_id = auth.uid() or public.buy_manager());
drop policy if exists "uta personal add" on public.uta_personal;
create policy "uta personal add" on public.uta_personal for insert to authenticated
  with check (public.buy_manager() or (user_id = auth.uid() and public.uta_tx_mine(tx_id)));
drop policy if exists "uta personal remove" on public.uta_personal;
create policy "uta personal remove" on public.uta_personal for delete to authenticated
  using (public.buy_manager() or user_id = auth.uid());

-- the member sees the UTA card(s) given to them and their fills (besides who sees „Transportas“)
drop policy if exists "uta cards own" on public.uta_cards;
create policy "uta cards own" on public.uta_cards for select to authenticated
  using (assign_kind = 'person' and person_id = auth.uid());
drop policy if exists "uta tx own" on public.uta_tx;
create policy "uta tx own" on public.uta_tx for select to authenticated
  using (public.uta_tx_mine(id));
-- managers check everyone's fills at month end
drop policy if exists "uta cards managers" on public.uta_cards;
create policy "uta cards managers" on public.uta_cards for select to authenticated using (public.buy_manager());
drop policy if exists "uta tx managers" on public.uta_tx;
create policy "uta tx managers" on public.uta_tx for select to authenticated using (public.buy_manager());

revoke all on public.expenses, public.uta_personal from anon;
grant select, insert, update, delete on public.expenses, public.uta_personal to authenticated;

-- receipts: <member>/<expense>/<file>; the member and the managers read, the member adds, both remove
insert into storage.buckets (id, name, public) values ('expense-files', 'expense-files', false) on conflict (id) do nothing;
drop policy if exists "expense files read" on storage.objects;
create policy "expense files read" on storage.objects for select to authenticated
  using (bucket_id = 'expense-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.buy_manager()));
drop policy if exists "expense files add" on storage.objects;
create policy "expense files add" on storage.objects for insert to authenticated
  with check (bucket_id = 'expense-files' and (storage.foldername(name))[1] = auth.uid()::text and public.is_approved());
drop policy if exists "expense files remove" on storage.objects;
create policy "expense files remove" on storage.objects for delete to authenticated
  using (bucket_id = 'expense-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.buy_manager()));

notify pgrst, 'reload schema';


-- „Išlaidos“: kilometrai prie kuro išlaidos (jei expenses.sql jau paleistas anksčiau)
-- Supabase → SQL Editor → New query → įklijuok → Run. Saugu paleisti pakartotinai.
alter table public.expenses add column if not exists km numeric(10,1);
notify pgrst, 'reload schema';


-- ============================================================
-- UTA kortelių PIN kodai ir bendros kortelės („Mano erdvė“ → UTA)
--  * uta_cards.shared – bendra kortelė: ją (ir jos PIN) mato visi patvirtinti nariai
--  * uta_pins         – kortelės PIN kodas atskiroje lentelėje:
--                       mato tas, kam kortelė priskirta, bendrų – visi patvirtinti nariai,
--                       ir kas redaguoja „Transportą“; keičia tik kas redaguoja „Transportą“.
-- Reikia: uta.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.uta_cards add column if not exists shared boolean not null default false;

create table if not exists public.uta_pins (
  card_id    uuid primary key references public.uta_cards(id) on delete cascade,
  pin        text not null check (pin ~ '^[0-9A-Za-z]{3,12}$'),
  updated_by uuid default auth.uid(),
  updated_at timestamptz not null default now()
);

-- the card is mine (given to me) or shared, and active
create or replace function public.uta_card_open(card uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.uta_cards c
                 where c.id = card and c.active
                   and (c.shared or (c.assign_kind = 'person' and c.person_id = auth.uid())))
$$;
grant execute on function public.uta_card_open(uuid) to authenticated;

alter table public.uta_pins enable row level security;
drop policy if exists "uta pins view" on public.uta_pins;
create policy "uta pins view" on public.uta_pins for select to authenticated
  using (public.can_edit('fleet') or (public.is_approved() and public.uta_card_open(card_id)));
drop policy if exists "uta pins edit" on public.uta_pins;
create policy "uta pins edit" on public.uta_pins for all to authenticated
  using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
revoke all on public.uta_pins from anon;
grant select, insert, update, delete on public.uta_pins to authenticated;

-- members see their own card and the shared ones
drop policy if exists "uta cards own" on public.uta_cards;
create policy "uta cards own" on public.uta_cards for select to authenticated
  using (assign_kind = 'person' and person_id = auth.uid());
drop policy if exists "uta cards shared" on public.uta_cards;
create policy "uta cards shared" on public.uta_cards for select to authenticated
  using (shared and public.is_approved());

notify pgrst, 'reload schema';


-- ============================================================
-- Ofisas → „Raktai“
--  * key_codes – sandėlio spynos kodai: sugeneruotas 4 skaitmenų kodas, kas ir kada sugeneravo,
--                kas ir kada pažymėjo, kad kodas ant spynos pakeistas
--  * key_loans – išduoti raktai: kam, kada, kas išdavė; kada grąžintas ir kas pažymėjo
--  * key_code_applied(id) – pažymi „kodas ant spynos pakeistas“ ir įdeda naują kodą
--                kanale #sandėlio-raktas (kanalą sukuria, jei jo nėra; nariai – kas mato „Raktus“)
-- Mato, kas mato „Raktus“ (Admin → teisės); keisti – kas juos redaguoja.
-- Reikia: user_roles.sql, members_chat.sql, chat_slack.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- skiltis „Raktai“ teisių lentelėje ----------
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people','newproj','invoices','buy','keys'));
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','keys',true,true), ('office','keys',true,true), ('tech','keys',true,true),
  ('freelance','keys',false,false), ('runner','keys',false,false)
on conflict (role, section) do nothing;

create table if not exists public.key_codes (
  id            uuid primary key default gen_random_uuid(),
  code          text not null check (code ~ '^[0-9]{4}$'),
  created_by    uuid default auth.uid(),
  created_name  text,
  created_at    timestamptz not null default now(),
  applied_at    timestamptz,
  applied_by    uuid,
  applied_name  text,
  cancelled_at  timestamptz
);
create index if not exists key_codes_created on public.key_codes (created_at desc);

create table if not exists public.key_loans (
  id             uuid primary key default gen_random_uuid(),
  key_name       text not null default 'Sandėlio raktas',
  holder_id      uuid,
  holder_name    text not null check (length(trim(holder_name)) > 0),
  given_at       timestamptz not null default now(),
  given_by       uuid,
  given_by_name  text,
  note           text not null default '',
  returned_at    timestamptz,
  returned_by    uuid,
  returned_name  text,
  created_by     uuid default auth.uid(),
  created_at     timestamptz not null default now()
);
create index if not exists key_loans_open on public.key_loans (returned_at, given_at desc);

alter table public.key_codes enable row level security;
alter table public.key_loans enable row level security;

drop policy if exists "key codes view" on public.key_codes;
create policy "key codes view" on public.key_codes for select to authenticated using (public.can_view('keys'));
drop policy if exists "key codes add" on public.key_codes;
create policy "key codes add" on public.key_codes for insert to authenticated
  with check (public.can_edit('keys') and applied_at is null);
drop policy if exists "key codes edit" on public.key_codes;
create policy "key codes edit" on public.key_codes for update to authenticated
  using (public.can_edit('keys')) with check (public.can_edit('keys'));
drop policy if exists "key codes remove" on public.key_codes;
create policy "key codes remove" on public.key_codes for delete to authenticated using (public.is_admin());

drop policy if exists "key loans view" on public.key_loans;
create policy "key loans view" on public.key_loans for select to authenticated using (public.can_view('keys'));
drop policy if exists "key loans add" on public.key_loans;
create policy "key loans add" on public.key_loans for insert to authenticated with check (public.can_edit('keys'));
drop policy if exists "key loans edit" on public.key_loans;
create policy "key loans edit" on public.key_loans for update to authenticated
  using (public.can_edit('keys')) with check (public.can_edit('keys'));
drop policy if exists "key loans remove" on public.key_loans;
create policy "key loans remove" on public.key_loans for delete to authenticated using (public.is_admin());

revoke all on public.key_codes, public.key_loans from anon;
grant select, insert, update, delete on public.key_codes, public.key_loans to authenticated;

-- who sees „Raktai“ (for the channel members)
create or replace function public.keys_viewer(uid uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles p where p.id = uid and (
    p.role = 'admin' or exists (select 1 from public.role_permissions rp
                                where rp.role = p.role and rp.section = 'keys' and (rp.can_view or rp.can_edit))))
$$;

-- the code is on the lock now: mark it and post it in #sandėlio-raktas
create or replace function public.key_code_applied(p_id uuid) returns uuid
  language plpgsql security definer set search_path = public as $$
declare k public.key_codes; cid uuid; who text; ts text;
begin
  if not public.can_edit('keys') then raise exception 'Nėra teisės keisti raktų.'; end if;
  select * into k from public.key_codes where id = p_id;
  if k.id is null then raise exception 'Kodas nerastas.'; end if;
  if k.cancelled_at is not null then raise exception 'Šis kodas atšauktas.'; end if;
  select coalesce(nullif(trim(coalesce(p.full_name, concat_ws(' ', p.first_name, p.last_name))), ''), p.email)
    into who from public.profiles p where p.id = auth.uid();
  if k.applied_at is null then
    update public.key_codes set applied_at = now(), applied_by = auth.uid(), applied_name = who where id = p_id
      returning * into k;
    -- older codes not put on the lock are left behind
    update public.key_codes set cancelled_at = now() where applied_at is null and cancelled_at is null and created_at < k.created_at;
  end if;
  select id into cid from public.conversations
   where kind = 'channel' and archived_at is null
     and lower(replace(replace(title, ' ', '-'), 'ė', 'e')) in ('sandelio-raktas', '#sandelio-raktas')
   order by created_at limit 1;
  if cid is null then
    insert into public.conversations (kind, title, topic, is_private, created_by)
    values ('channel', 'sandėlio-raktas', 'Sandėlio spynos kodai (iš Ofisas → Raktai)', true, auth.uid()) returning id into cid;
  end if;
  insert into public.conversation_members (conversation_id, user_id)
  select cid, p.id from public.profiles p
   where (p.id = auth.uid() or public.keys_viewer(p.id)) and public.user_can_chat(p.id)
  on conflict do nothing;
  ts := to_char(k.applied_at at time zone 'Europe/Vilnius', 'YYYY-MM-DD HH24:MI');
  insert into public.messages (conversation_id, sender_id, body)
  values (cid, auth.uid(), '🔑 Naujas sandėlio rakto kodas: ' || k.code || E'\nKodas ant spynos pakeistas ' || ts || coalesce(' (' || who || ')', '') || '.');
  return cid;
end $$;
grant execute on function public.key_code_applied(uuid) to authenticated;

notify pgrst, 'reload schema';


-- ============================================================
-- Ofisas → „Signalizacija“
--  * alarm_staff_codes – darbuotojų signalizacijos kodai: mato ir keičia TIK Admin ir Office
--  * alarm_temp_codes  – laikini kodai: atsitiktinis 4 skaitmenų kodas, kam (el. paštas), iki kada galioja.
--                        Pasibaigus galiojimui kodą reikia ištrinti arba pakeisti – tada jis
--                        uždaromas (closed_kind = 'deleted' / 'changed') ir rodomas Archyve.
-- Laikinus kodus mato, kas mato „Signalizaciją“ (Admin → teisės); keisti – kas ją redaguoja.
-- Reikia: user_roles.sql (ir keys.sql – teisių sąraše jau yra „keys“).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- skiltis „Signalizacija“ teisių lentelėje ----------
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people','newproj','invoices','buy','keys','alarm'));
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','alarm',true,true), ('office','alarm',true,true), ('tech','alarm',false,false),
  ('freelance','alarm',false,false), ('runner','alarm',false,false)
on conflict (role, section) do nothing;

create table if not exists public.alarm_staff_codes (
  id           uuid primary key default gen_random_uuid(),
  person_id    uuid,
  person_name  text not null check (length(trim(person_name)) > 0),
  code         text not null check (code ~ '^[0-9]{4,8}$'),
  note         text not null default '',
  created_by   uuid default auth.uid(),
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),
  updated_name text
);

create table if not exists public.alarm_temp_codes (
  id            uuid primary key default gen_random_uuid(),
  code          text not null check (code ~ '^[0-9]{4}$'),
  email         text not null check (length(trim(email)) > 0),
  note          text not null default '',
  valid_from    timestamptz not null default now(),
  valid_until   timestamptz not null,
  created_by    uuid default auth.uid(),
  created_name  text,
  created_at    timestamptz not null default now(),
  closed_at     timestamptz,
  closed_kind   text check (closed_kind in ('deleted','changed')),
  closed_by     uuid,
  closed_name   text,
  replaced_by   uuid
);
create index if not exists alarm_temp_open on public.alarm_temp_codes (closed_at, valid_until);

-- the staff codes: Admin and Office only (by the real level)
create or replace function public.alarm_staff_ok() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','office'), false)
$$;
grant execute on function public.alarm_staff_ok() to authenticated;

alter table public.alarm_staff_codes enable row level security;
alter table public.alarm_temp_codes enable row level security;

drop policy if exists "alarm staff all" on public.alarm_staff_codes;
create policy "alarm staff all" on public.alarm_staff_codes for all to authenticated
  using (public.alarm_staff_ok()) with check (public.alarm_staff_ok());

drop policy if exists "alarm temp view" on public.alarm_temp_codes;
create policy "alarm temp view" on public.alarm_temp_codes for select to authenticated using (public.can_view('alarm'));
drop policy if exists "alarm temp add" on public.alarm_temp_codes;
create policy "alarm temp add" on public.alarm_temp_codes for insert to authenticated
  with check (public.can_edit('alarm') and closed_at is null);
drop policy if exists "alarm temp edit" on public.alarm_temp_codes;
create policy "alarm temp edit" on public.alarm_temp_codes for update to authenticated
  using (public.can_edit('alarm')) with check (public.can_edit('alarm'));
drop policy if exists "alarm temp remove" on public.alarm_temp_codes;
create policy "alarm temp remove" on public.alarm_temp_codes for delete to authenticated using (public.is_admin());

revoke all on public.alarm_staff_codes, public.alarm_temp_codes from anon;
grant select, insert, update, delete on public.alarm_staff_codes, public.alarm_temp_codes to authenticated;

notify pgrst, 'reload schema';


-- ============================================================
-- Signalizacija → Laikinas kodas: privalomas vardas, pavardė; el. paštas nebūtinas.
-- Tik jei alarm.sql jau buvo paleistas anksčiau (naujas alarm.sql tai jau turi).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.alarm_temp_codes add column if not exists person_name text;
alter table public.alarm_temp_codes alter column email drop not null;
alter table public.alarm_temp_codes drop constraint if exists alarm_temp_codes_email_check;
notify pgrst, 'reload schema';


-- ============================================================
-- Transportas: tepalo keitimas, moto valandos ir profilaktika
--  * engine_hours – moto valandos (prie bet kurio įrašo, kaip ir rida)
--  * data (jsonb) – papildomi duomenys:
--      tepalo keitimas (kind 'service', kategorija „Tepalo keitimas“):
--        { oil:{ type, liters, next_km, next_hours, next_date } }
--      profilaktika (kind 'check'):
--        { fluids:{ washer:{v,u}, oil:{v,u}, antifreeze:{v,u} }, condition:'good'|'fair'|'bad' }
--  * kind 'check' – profilaktika: gali įrašyti kiekvienas, kas mato „Transportą“ (kaip ir problemą)
-- Reikia: vehicle_logs.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.vehicle_logs add column if not exists engine_hours numeric(10,1)
  check (engine_hours is null or (engine_hours >= 0 and engine_hours < 1000000));
alter table public.vehicle_logs add column if not exists data jsonb not null default '{}'::jsonb;

alter table public.vehicle_logs drop constraint if exists vehicle_logs_kind_check;
alter table public.vehicle_logs add constraint vehicle_logs_kind_check check (kind in ('service','problem','check'));

drop policy if exists "fleet logs add" on public.vehicle_logs;
create policy "fleet logs add" on public.vehicle_logs for insert to authenticated
  with check (public.can_view('fleet') and created_by = auth.uid() and (kind in ('problem','check') or public.can_edit('fleet')));
drop policy if exists "fleet logs change" on public.vehicle_logs;
create policy "fleet logs change" on public.vehicle_logs for update to authenticated
  using (public.can_edit('fleet') or created_by = auth.uid())
  with check (public.can_edit('fleet') or (created_by = auth.uid() and kind in ('problem','check')));

notify pgrst, 'reload schema';


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


-- ============================================================
-- Automobilio QR kodas niekada nesikeičia: kodo pašalinti / pakeisti nebegalima.
-- Tik jei vehicle_qr.sql jau buvo paleistas anksčiau (naujas vehicle_qr.sql tai jau turi).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
drop policy if exists "vehicle qr remove" on public.vehicle_qr;
revoke update, delete on public.vehicle_qr from authenticated;
notify pgrst, 'reload schema';


-- ============================================================
-- Ataskaitos → „Ofiso valymas“, „Bolt“ ir „Wolt“
--  * office_cleanings – ofiso valymai: kada užsakyta valytoja, kada atliktas valymas, kaina, pastabos.
--                       Mato, kas mato „Ataskaitas“; įrašo / keičia Admin, Office, Projektų vadovas.
--  * bolt_reports     – kas mėnesį įkeliami Bolt dokumentai (PDF / Excel / CSV), failai – saugykla 'bolt-files'
--  * bolt_trips       – kelionės iš Excel / CSV: kas, kada, iš kur, į kur, kiek kainavo, pastaba (tikslas);
--                       kind 'work' / 'personal' (be pastabos, „P“ ar „asmeninė“ – asmeninė; su tikslu – darbo),
--                       tikrinant galima pakeisti ranka.
--                       Visas keliones mato ir tvarko TIK Admin ir Office; narys mato tik savo (person_id).
--  * bolt_rules       – žodžiai / frazės, pagal kuriuos kelionė priskiriama asmeninei ar darbo
--  * wolt_reports / wolt_orders – kas mėnesį įkeliama Wolt suvestinė (PDF / Excel / CSV) ir jos užsakymai;
--                       mėnesio suma ir užsakymų skaičius (jei dokumentas be lentelės – įrašomi ranka).
--                       Mato ir tvarko Admin ir Office.
-- Reikia: user_roles.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.office_admin() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','office'), false)
$$;
grant execute on function public.office_admin() to authenticated;

-- ---------- Ofiso valymas ----------
create table if not exists public.office_cleanings (
  id            uuid primary key default gen_random_uuid(),
  ordered_on    date,
  done_on       date,
  cleaner       text not null default '',
  cost          numeric(12,2) check (cost is null or (cost >= 0 and cost < 1000000)),
  note          text not null default '',
  created_by    uuid default auth.uid(),
  created_name  text,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create index if not exists office_cleanings_done on public.office_cleanings (done_on desc);
alter table public.office_cleanings enable row level security;
drop policy if exists "cleanings view" on public.office_cleanings;
create policy "cleanings view" on public.office_cleanings for select to authenticated
  using (public.can_view('stats') or public.my_role() in ('admin','office','pm'));
drop policy if exists "cleanings edit" on public.office_cleanings;
create policy "cleanings edit" on public.office_cleanings for all to authenticated
  using (public.my_role() in ('admin','office','pm')) with check (public.my_role() in ('admin','office','pm'));
revoke all on public.office_cleanings from anon;
grant select, insert, update, delete on public.office_cleanings to authenticated;

-- ---------- Bolt ----------
create table if not exists public.bolt_reports (
  id            uuid primary key default gen_random_uuid(),
  month         text not null check (month ~ '^[0-9]{4}-[0-9]{2}$'),
  file_name     text not null default '',
  file_path     text,
  file_type     text,
  trips         integer not null default 0,
  note          text not null default '',
  uploaded_by   uuid default auth.uid(),
  uploaded_name text,
  created_at    timestamptz not null default now()
);
create index if not exists bolt_reports_month on public.bolt_reports (month desc);

create table if not exists public.bolt_trips (
  id            uuid primary key default gen_random_uuid(),
  report_id     uuid not null references public.bolt_reports(id) on delete cascade,
  trip_at       timestamptz,
  trip_on       date,
  person_name   text not null default '',
  phone         text,
  person_id     uuid,
  from_addr     text not null default '',
  to_addr       text not null default '',
  amount        numeric(12,2),
  note          text not null default '',
  kind          text not null default 'personal' check (kind in ('work','personal')),
  kind_manual   boolean not null default false,
  checked_by    uuid,
  checked_name  text,
  checked_at    timestamptz
);
create index if not exists bolt_trips_report on public.bolt_trips (report_id);
create index if not exists bolt_trips_person on public.bolt_trips (person_id, trip_on);
create index if not exists bolt_trips_on on public.bolt_trips (trip_on);

alter table public.bolt_reports enable row level security;
alter table public.bolt_trips enable row level security;
drop policy if exists "bolt reports all" on public.bolt_reports;
create policy "bolt reports all" on public.bolt_reports for all to authenticated
  using (public.office_admin()) with check (public.office_admin());
drop policy if exists "bolt trips manage" on public.bolt_trips;
create policy "bolt trips manage" on public.bolt_trips for all to authenticated
  using (public.office_admin()) with check (public.office_admin());
-- a member sees only own trips
drop policy if exists "bolt trips own" on public.bolt_trips;
create policy "bolt trips own" on public.bolt_trips for select to authenticated
  using (person_id = auth.uid() and public.is_approved());
revoke all on public.bolt_reports, public.bolt_trips from anon;
grant select, insert, update, delete on public.bolt_reports, public.bolt_trips to authenticated;

-- the words / phrases that sort the trips (Admin and Office edit them)
create table if not exists public.bolt_rules (
  id          integer primary key default 1 check (id = 1),
  personal    text[] not null default '{}',
  work        text[] not null default '{}',
  updated_by  uuid,
  updated_at  timestamptz not null default now()
);
insert into public.bolt_rules (id) values (1) on conflict (id) do nothing;
alter table public.bolt_rules enable row level security;
drop policy if exists "bolt rules all" on public.bolt_rules;
create policy "bolt rules all" on public.bolt_rules for all to authenticated
  using (public.office_admin()) with check (public.office_admin());
revoke all on public.bolt_rules from anon;
grant select, insert, update on public.bolt_rules to authenticated;

-- ---------- Wolt ----------
create table if not exists public.wolt_reports (
  id            uuid primary key default gen_random_uuid(),
  month         text not null check (month ~ '^[0-9]{4}-[0-9]{2}$'),
  file_name     text not null default '',
  file_path     text,
  file_type     text,
  orders        integer not null default 0,
  total         numeric(12,2),
  note          text not null default '',
  uploaded_by   uuid default auth.uid(),
  uploaded_name text,
  created_at    timestamptz not null default now()
);
create index if not exists wolt_reports_month on public.wolt_reports (month desc);
create table if not exists public.wolt_orders (
  id            uuid primary key default gen_random_uuid(),
  report_id     uuid not null references public.wolt_reports(id) on delete cascade,
  order_at      timestamptz,
  order_on      date,
  person_name   text not null default '',
  venue         text not null default '',
  amount        numeric(12,2),
  note          text not null default ''
);
create index if not exists wolt_orders_report on public.wolt_orders (report_id);
create index if not exists wolt_orders_on on public.wolt_orders (order_on);
alter table public.wolt_reports enable row level security;
alter table public.wolt_orders enable row level security;
drop policy if exists "wolt reports all" on public.wolt_reports;
create policy "wolt reports all" on public.wolt_reports for all to authenticated
  using (public.office_admin()) with check (public.office_admin());
drop policy if exists "wolt orders all" on public.wolt_orders;
create policy "wolt orders all" on public.wolt_orders for all to authenticated
  using (public.office_admin()) with check (public.office_admin());
revoke all on public.wolt_reports, public.wolt_orders from anon;
grant select, insert, update, delete on public.wolt_reports, public.wolt_orders to authenticated;

-- the documents (Bolt and Wolt): <bolt|wolt>/<month>/<id>.<ext>
insert into storage.buckets (id, name, public) values ('bolt-files', 'bolt-files', false) on conflict (id) do nothing;
drop policy if exists "bolt files read" on storage.objects;
create policy "bolt files read" on storage.objects for select to authenticated using (bucket_id = 'bolt-files' and public.office_admin());
drop policy if exists "bolt files add" on storage.objects;
create policy "bolt files add" on storage.objects for insert to authenticated with check (bucket_id = 'bolt-files' and public.office_admin());
drop policy if exists "bolt files remove" on storage.objects;
create policy "bolt files remove" on storage.objects for delete to authenticated using (bucket_id = 'bolt-files' and public.office_admin());

notify pgrst, 'reload schema';


-- ============================================================
-- Bolt / Wolt: failas išsaugomas ir tada, kai saugykla „bolt-files“ jo nepriima
-- (failas laikomas duomenų bazėje, iki 8 MB), ir diagnostika, kodėl nepavyksta įkelti.
-- Reikia: office_bolt.sql. Saugu paleisti pakartotinai.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- ============================================================

create table if not exists public.office_files (
  id          uuid primary key default gen_random_uuid(),
  kind        text not null default 'bolt' check (kind in ('bolt','wolt')),
  report_id   uuid,
  name        text not null default '',
  type        text,
  size        integer,
  data        text not null,                 -- base64
  created_by  uuid default auth.uid(),
  created_at  timestamptz not null default now()
);
alter table public.office_files enable row level security;
drop policy if exists "office files all" on public.office_files;
create policy "office files all" on public.office_files for all to authenticated
  using (public.office_admin()) with check (public.office_admin());
revoke all on public.office_files from anon;
grant select, insert, delete on public.office_files to authenticated;

-- what the server thinks of the one who uploads
create or replace function public.office_whoami() returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'role', public.my_role(),
    'office_admin', public.office_admin(),
    'bucket', exists (select 1 from storage.buckets where id = 'bolt-files'),
    'policies', coalesce((select jsonb_agg(policyname) from pg_policies where schemaname = 'storage' and tablename = 'objects' and policyname like 'bolt files%'), '[]'::jsonb),
    'tables', exists (select 1 from information_schema.tables where table_schema = 'public' and table_name = 'bolt_reports'))
$$;
grant execute on function public.office_whoami() to authenticated;

notify pgrst, 'reload schema';


-- ============================================================
-- Bolt: kelionės automobilio kategorija (Vehicle category group iš Bolt Excel).
-- Tik jei office_bolt.sql jau buvo paleistas anksčiau. Saugu paleisti pakartotinai.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- ============================================================
alter table public.bolt_trips add column if not exists vehicle_cat text;
notify pgrst, 'reload schema';


-- ============================================================
-- Bolt / Wolt teisės pagal lygius
--  * Admin           – mato viską: kelionių kainas, sumas, Wolt išlaidas
--  * Office          – įkelia Bolt dokumentus, mato kas ir kiek kelionių atliko, keičia „darbo / asmeninė“,
--                      bet KAINŲ NEGAUNA (stulpelis amount jam neperduodamas)
--  * Projektų vadovas, Tech – mato tik savo keliones (su savo kainomis)
--  * Freelance, Runner – Bolt nemato
--  Kainos gaunamos tik per bolt_trip_amounts(): Admin – visos, kiti – tik savo kelionių.
--  Wolt (išlaidos) – tik Admin.
-- Reikia: office_bolt.sql (ir office_bolt3.sql). Saugu paleisti pakartotinai.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- ============================================================

-- the trips: every column except the price can be read (the rows themselves follow the policies below)
revoke select on public.bolt_trips from authenticated;
grant select (id, report_id, trip_at, trip_on, person_name, phone, vehicle_cat, person_id, from_addr, to_addr, note, kind, kind_manual, checked_by, checked_name, checked_at)
  on public.bolt_trips to authenticated;
grant insert, update, delete on public.bolt_trips to authenticated;

drop policy if exists "bolt trips own" on public.bolt_trips;
create policy "bolt trips own" on public.bolt_trips for select to authenticated
  using (person_id = auth.uid() and coalesce(public.my_role() in ('admin','pm','office','tech'), false));

-- the prices: Admin all, the others only their own trips
create or replace function public.bolt_trip_amounts(p_ids uuid[]) returns table (id uuid, amount numeric)
  language sql stable security definer set search_path = public as $$
  select t.id, t.amount from public.bolt_trips t
   where t.id = any(p_ids)
     and (public.my_role() = 'admin' or (t.person_id = auth.uid() and public.my_role() in ('pm','office','tech')))
$$;
revoke all on function public.bolt_trip_amounts(uuid[]) from public, anon;
grant execute on function public.bolt_trip_amounts(uuid[]) to authenticated;

-- Wolt: only Admin
drop policy if exists "wolt reports all" on public.wolt_reports;
create policy "wolt reports all" on public.wolt_reports for all to authenticated
  using (public.is_admin()) with check (public.is_admin());
drop policy if exists "wolt orders all" on public.wolt_orders;
create policy "wolt orders all" on public.wolt_orders for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

notify pgrst, 'reload schema';


-- ============================================================
-- „Išlaidos“: mėnesinis kompensavimo limitas nariui
--  * expense_allowance – kiek € nariui pridedama kiekvieną mėnesį (nuo kurio mėnesio);
--                        nepanaudotas likutis pereina į kitą mėnesį
--  * expenses.from_allow – išlaida apmokama iš sukaupto likučio (varnelė pildant)
-- Narys mato savo limitą; Admin / Office / Projektų vadovas – visų; nustato Admin / Office.
-- Reikia: expenses.sql, office_bolt.sql (office_admin).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.expense_allowance (
  user_id     uuid primary key references auth.users(id) on delete cascade,
  monthly     numeric(12,2) not null check (monthly >= 0),
  start_month date not null default date_trunc('month', now())::date,
  set_by      uuid default auth.uid(),
  updated_at  timestamptz not null default now()
);
alter table public.expenses add column if not exists from_allow boolean not null default false;

alter table public.expense_allowance enable row level security;
drop policy if exists "allowance view" on public.expense_allowance;
create policy "allowance view" on public.expense_allowance for select to authenticated
  using (user_id = auth.uid() or public.buy_manager());
drop policy if exists "allowance set" on public.expense_allowance;
create policy "allowance set" on public.expense_allowance for all to authenticated
  using (public.office_admin()) with check (public.office_admin());

revoke all on public.expense_allowance from anon;
grant select, insert, update, delete on public.expense_allowance to authenticated;

notify pgrst, 'reload schema';


-- ============================================================
-- Team Tracker: darbo pradžios ir pabaigos vieta
--  * time_shifts.start_loc / end_loc – {lat, lng, acc (m), addr} arba {err:'denied'|'fail'|'none'}
--  * tt_loc(...) – telefonas atsiunčia vietą paspaudus „Pradėti darbą“ / „Baigti darbą“
--  * tt_shift_json – pamainoje grąžina ir vietas (rodomos suvestinėse)
-- Reikia: tracker.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.time_shifts add column if not exists start_loc jsonb;
alter table public.time_shifts add column if not exists end_loc jsonb;

create or replace function public.tt_shift_json(sid uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', s.id, 'started_at', s.started_at, 'ended_at', s.ended_at,
    'start_loc', s.start_loc, 'end_loc', s.end_loc,
    'entries', coalesce((select jsonb_agg(jsonb_build_object('kind', e.kind, 'started_at', e.started_at, 'ended_at', e.ended_at) order by e.started_at)
                         from public.time_entries e where e.shift_id = s.id), '[]'::jsonb))
  from public.time_shifts s where s.id = sid
$$;

-- p_which: 'start' – ką tik pradėta pamaina; 'end' – ką tik baigta pamaina
create or replace function public.tt_loc(m uuid, p_token text, p_which text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid; loc jsonb;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  -- only the known keys, short values
  loc := jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20),
    'late', case when (p_loc->>'late') = 'true' then true end,
    'at', now()));
  if p_which = 'start' then
    select id into sid from public.time_shifts where member_id = m and start_loc is null and started_at > now() - interval '30 minutes'
      order by started_at desc limit 1;
    if sid is not null then update public.time_shifts set start_loc = loc where id = sid; end if;
  elsif p_which = 'end' then
    select id into sid from public.time_shifts where member_id = m and ended_at is not null and end_loc is null
      order by ended_at desc limit 1;
    if sid is not null then update public.time_shifts set end_loc = loc where id = sid; end if;
  end if;
  return jsonb_build_object('ok', sid is not null);
end $$;
revoke all on function public.tt_loc(uuid, text, text, jsonb) from public, anon;
grant execute on function public.tt_loc(uuid, text, text, jsonb) to authenticated;

notify pgrst, 'reload schema';


-- ============================================================
-- „Išlaidos“: kompensacija eurais ARBA litrais
--  * expenses.comp_unit   – 'eur' (kompensacija €) arba 'l' (kompensacija litrais kuro)
--  * uta_personal.unit    – asmeninis UTA pylimas atimamas iš sukauptų € ('eur') arba litrų ('l')
-- Reikia: expenses.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.expenses add column if not exists comp_unit text not null default 'eur';
alter table public.expenses drop constraint if exists expenses_comp_unit_check;
alter table public.expenses add constraint expenses_comp_unit_check check (comp_unit in ('eur','l'));
alter table public.uta_personal add column if not exists unit text not null default 'eur';
alter table public.uta_personal drop constraint if exists uta_personal_unit_check;
alter table public.uta_personal add constraint uta_personal_unit_check check (unit in ('eur','l'));
notify pgrst, 'reload schema';


-- ============================================================
-- „Išlaidos“: narys pats taiso ir trina savo išlaidas bet kada
--  * pataisyta išlaida vėl laukia patikros (status 'new'), kompensacija nuimama
--  * ištrinti savo išlaidą galima ir patvirtintą / atmestą
-- Reikia: expenses.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
drop policy if exists "expenses edit" on public.expenses;
create policy "expenses edit" on public.expenses for update to authenticated
  using (public.buy_manager() or user_id = auth.uid())
  with check (public.buy_manager() or (user_id = auth.uid() and status = 'new' and comp is null));
drop policy if exists "expenses remove" on public.expenses;
create policy "expenses remove" on public.expenses for delete to authenticated
  using (public.buy_manager() or user_id = auth.uid());
notify pgrst, 'reload schema';


-- ============================================================
-- „Išlaidos“: kuro pylimas iš sukaupto kompensacijų likučio
--  * comp_use – narys pažymi, kad prisipylė kuro iš sukaupto likučio
--               (litrais arba eurais); atimama iš jo likučio
-- Narys mato, prideda ir trina savo; Admin / Office / Projektų vadovas – visų.
-- Reikia: expenses.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.comp_use (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  used_on    date not null default current_date,
  unit       text not null default 'l' check (unit in ('eur','l')),
  liters     numeric(10,2),
  amount     numeric(12,2),
  note       text not null default '',
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now()
);
create index if not exists comp_use_user on public.comp_use (user_id, used_on);

alter table public.comp_use enable row level security;
drop policy if exists "comp use view" on public.comp_use;
create policy "comp use view" on public.comp_use for select to authenticated
  using (user_id = auth.uid() or public.buy_manager());
drop policy if exists "comp use add" on public.comp_use;
create policy "comp use add" on public.comp_use for insert to authenticated
  with check ((user_id = auth.uid() and public.is_approved()) or public.buy_manager());
drop policy if exists "comp use remove" on public.comp_use;
create policy "comp use remove" on public.comp_use for delete to authenticated
  using (user_id = auth.uid() or public.buy_manager());

revoke all on public.comp_use from anon;
grant select, insert, delete on public.comp_use to authenticated;
notify pgrst, 'reload schema';


-- ============================================================
-- „Išlaidos“: mokėjimo būdas „Iš savo kuro“ (paid = 'tank')
--  kuras iš savo automobilio bako – be kvito ir be sumos
-- Reikia: expenses.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.expenses drop constraint if exists expenses_paid_check;
alter table public.expenses add constraint expenses_paid_check check (paid in ('uta','own','tank'));
notify pgrst, 'reload schema';


-- ============================================================
-- Pasiūlymų kūrimas → Įranga / Paslaugos
--  * Įranga – sandėlio daiktų pavadinimai, vienetai ir kainos pasiūlymams;
--  * Įrangos grupės – kelių daiktų rinkiniai kaip viena pasiūlymo eilutė (pvz. 1 m² ekrano);
--  * Paslaugos – pavadinimai ir įkainiai;
--  * Kita – kas pasiūlymuose įrašyta ranka (išsaugoma savaime).
-- Mato tie, kas mato „Pasiūlymų kūrimą“, keičia – kas jį redaguoja.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.offer_catalog (
  id         text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);
alter table public.offer_catalog enable row level security;
drop policy if exists "view offer catalog" on public.offer_catalog;
create policy "view offer catalog" on public.offer_catalog
  for select to authenticated using (public.can_view('offers'));
drop policy if exists "edit offer catalog" on public.offer_catalog;
create policy "edit offer catalog" on public.offer_catalog
  for all to authenticated using (public.can_edit('offers')) with check (public.can_edit('offers'));
grant select, insert, update, delete on public.offer_catalog to authenticated;
revoke all on public.offer_catalog from anon;

-- Supabase: read the list of tables again (otherwise the app may still say the table is missing)
notify pgrst, 'reload schema';


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


-- ============================================================
-- El. paštas: persiųsti laiškai atsidaro iš karto (net dideli)
--  * pašto serveris kiekvieną naują laišką persiunčia į <vardas>@in.eventsolutions.lt
--  * Cloudflare Email Routing → Email Worker (cloudflare/mail-in-worker.js) → „mail-in“ funkcija
--  * mail_in – laiško turinys, siuntėjas, gavėjai, priedų sąrašas
--  * saugykla „mail-in“ – priedai (<narys>/<laiškas>/<failas>)
--  * kiekvienas mato TIK SAVO laiškus; rašo tik „mail-in“ funkcija; laikoma 120 d.
-- Reikia: mail.sql. Funkcija: supabase functions deploy mail-in --no-verify-jwt
--         ir slaptas raktas: supabase secrets set MAIL_IN_SECRET=<ilgas atsitiktinis tekstas>
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.mail_in (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users(id) on delete cascade,
  message_id  text,
  date        timestamptz,
  subject     text not null default '',
  from_addr   jsonb not null default '[]'::jsonb,
  to_addr     jsonb not null default '[]'::jsonb,
  cc_addr     jsonb not null default '[]'::jsonb,
  reply_to    jsonb not null default '[]'::jsonb,
  refs        jsonb not null default '[]'::jsonb,
  html        text not null default '',
  text        text not null default '',
  attachments jsonb not null default '[]'::jsonb,
  size        integer,
  created_at  timestamptz not null default now()
);
create index if not exists mail_in_find on public.mail_in (user_id, date desc);
create index if not exists mail_in_msgid on public.mail_in (user_id, message_id);

alter table public.mail_in enable row level security;
drop policy if exists "own forwarded mail" on public.mail_in;
create policy "own forwarded mail" on public.mail_in for select to authenticated using (user_id = auth.uid());
revoke all on public.mail_in from anon;
revoke insert, update, delete on public.mail_in from authenticated;
grant select on public.mail_in to authenticated;

-- attachments: private, each member reads only their own folder
insert into storage.buckets (id, name, public, file_size_limit) values ('mail-in', 'mail-in', false, 52428800)
on conflict (id) do update set public = false;
drop policy if exists "own forwarded mail files" on storage.objects;
create policy "own forwarded mail files" on storage.objects for select to authenticated
  using (bucket_id = 'mail-in' and (storage.foldername(name))[1] = auth.uid()::text);

-- signed out of mail: the forwarded letters go too
create or replace function public.mail_in_cleanup() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  delete from public.mail_in where user_id = old.user_id;
  return old;
end $$;
drop trigger if exists mail_in_cleanup on public.mail_accounts;
create trigger mail_in_cleanup after delete on public.mail_accounts for each row execute function public.mail_in_cleanup();

notify pgrst, 'reload schema';


-- ============================================================
-- El. paštas: „Gauti per Gmail“
--  * pašto serveris (serveriai.lt) persiunčia laiškus į Gmail; programa juos skaito iš Gmail
--    (greita, dideli laiškai atsidaro iš karto), o siunčia kaip anksčiau – iš @eventsolutions.lt
--  * Gmail programos slaptažodis saugomas užšifruotas (kaip ir pašto slaptažodis)
-- Reikia: mail.sql ir „mail“ funkcija v15 (supabase functions deploy mail).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.mail_accounts add column if not exists reader jsonb;
notify pgrst, 'reload schema';



-- Gmail skirtukai (Pagrindiniai, Reklamos, Socialiniai, Naujienos, Forumai): kiekvieno laiško kategorija
alter table public.mail_index add column if not exists cat text;
create index if not exists mail_index_cat on public.mail_index (user_id, folder, cat, date desc nulls last);
notify pgrst, 'reload schema';


-- ============================================================
-- El. paštas: nauji laiškai tikrinami kas 15 sekundžių (ne kas minutę)
--  * „mail-sync-fast“ – greitas patikrinimas: ar atėjo naujų laiškų (+ pranešimas telefone
--    ir kompiuteryje), paruošiami keli naujausi; pilnas tikrinimas („mail-sync“) lieka kas minutę
-- Reikia: mail_viskas.sql (jau paleistas – „mail-sync“ veikia) ir „mail“ funkcija v17.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
do $$
declare secret text;
begin
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
    from cron.job where jobname = 'mail-sync';
  if secret is null then
    select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
      from cron.job where jobname = 'vehicle-reminders-daily';
  end if;
  if secret is null then raise exception 'Nerastas CRON_SECRET – pirmiausia paleisk mail_viskas.sql.'; end if;
  perform cron.unschedule(jobid) from cron.job where jobname = 'mail-sync-fast';
  perform cron.schedule('mail-sync-fast', '15 seconds', format($job$
    select net.http_post(
      url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/mail',
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', %L),
      body    := '{"action":"sync_all","quick":true}'::jsonb,
      timeout_milliseconds := 30000
    );
  $job$, secret));
end $$;
select jobname, schedule, active from cron.job where jobname like 'mail-sync%';

-- laiškų sąraše po tema – teksto pradžia (kaip Gmail)
alter table public.mail_index add column if not exists snippet text;
notify pgrst, 'reload schema';


-- ============================================================
-- El. paštas: „Visi / Darbo / Asmeniniai“ – kiekvienas laiškas pažymimas, ar jis darbo
-- (gavėjas arba kopija – …@eventsolutions.lt; išsiųstuose – siuntėjas). Seni laiškai pažymimi
-- automatiškai per kelias minutes. Reikia: mail_viskas.sql ir „mail“ funkcija v19.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.mail_index add column if not exists acct text;
alter table public.mail_index add column if not exists snippet text;
create index if not exists mail_index_acct on public.mail_index (user_id, folder, acct, date desc nulls last);
notify pgrst, 'reload schema';


-- ============================================================
-- El. paštas: automatinis atsakymas („ne biure“) – kas minutę, ne kas 10 min.
--  * atsakymai dabar siunčiami kartu su pašto tikrinimu („mail-sync“, kas minutę),
--    todėl senas 10 minučių darbas išjungiamas (kad neatsakytų du kartus)
-- Reikia: „mail“ funkcija v22.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
select cron.unschedule(jobid) from cron.job where jobname = 'mail-auto-reply';
select jobname, schedule, active from cron.job where jobname like 'mail%';

-- ============================================================
-- Freelancerių sąskaitos: saskaitos.eventsolutions.lt
--  * freelanceris įveda el. paštą → gauna vienkartinį PIN (galioja 1 val.) → užpildo,
--    kuriuose renginiuose dirbo (sutarta suma arba valandinis), įkelia sąskaitą;
--    sumos sulyginamos ir sąskaita atsiranda „Sąskaitose“ → Freelance su išskaidymu
--  * fl_portal_pins / fl_portal_sessions – tik serverio funkcijai „freelance-portal“
--  * invoices: kas pateikė (ext_email, ext_name), eilutės (lines), šaltinis (source)
-- Reikia: invoices.sql. Funkcija: supabase functions deploy freelance-portal --no-verify-jwt
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.invoices add column if not exists ext_email text;
alter table public.invoices add column if not exists ext_name  text;
alter table public.invoices add column if not exists lines     jsonb;
alter table public.invoices add column if not exists source    text;

create table if not exists public.fl_portal_pins (
  id          uuid primary key default gen_random_uuid(),
  email       text not null,
  pin_hash    text not null,
  expires_at  timestamptz not null,
  attempts    integer not null default 0,
  used_at     timestamptz,
  created_at  timestamptz not null default now()
);
create index if not exists fl_portal_pins_email on public.fl_portal_pins (email, created_at desc);

create table if not exists public.fl_portal_sessions (
  token_hash  text primary key,
  email       text not null,
  name        text,
  contact_id  text,
  expires_at  timestamptz not null,
  created_at  timestamptz not null default now()
);

-- tik serverio funkcija (service role): jokių taisyklių programai ar svečiams
alter table public.fl_portal_pins enable row level security;
alter table public.fl_portal_sessions enable row level security;
revoke all on public.fl_portal_pins, public.fl_portal_sessions from anon, authenticated;

notify pgrst, 'reload schema';

-- ============================================================
-- Freelancerių sąskaitos (2): laiškai freelanceriui
--  * nepatvirtinta → laiškas su priežastimi ir mygtuku „Taisyti sąskaitą“
--  * patvirtinta → „patvirtinta, perduota buhalterijai“; apmokėta → „apmokėta“
--  * ext_mailed – kas jau pranešta (tas pats laiškas antrą kartą nesiunčiamas)
-- Reikia: freelance_portal.sql. Funkcijos: freelance-portal, push-notify (naujos versijos).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.invoices add column if not exists ext_mailed text;
create index if not exists invoices_ext_email_idx on public.invoices (ext_email) where source = 'portal';

notify pgrst, 'reload schema';

-- ============================================================
-- Freelancerių sąskaitos (3): laiškas freelanceriui išeina pats
--  * kai portalo sąskaitos būsena pasikeičia (netvirtinta / patvirtinta / apmokėta),
--    duomenų bazė iškart kviečia „push-notify“ – laiškas išsiunčiamas nepriklausomai
--    nuo to, kokia programos versija atidaryta
--  * ext_mailed – kas jau pranešta (antras toks pat laiškas nesiunčiamas)
-- Reikia: freelance_portal.sql ir mail_viskas.sql (ar kitas cron su x-cron-secret).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create extension if not exists pg_net;
alter table public.invoices add column if not exists ext_mailed text;
create index if not exists invoices_ext_email_idx on public.invoices (ext_email) where source = 'portal';

create or replace function public.invoices_portal_mail() returns trigger
  language plpgsql security definer set search_path = public, extensions as $$
declare secret text;
begin
  if new.source is distinct from 'portal' or new.status is not distinct from old.status
     or new.status not in ('rejected','approved','sent','queued','paid') then
    return new;
  end if;
  -- the cron secret the scheduled jobs already use
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
    from cron.job where command like '%x-cron-secret%' order by jobid limit 1;
  if secret is null then return new; end if;
  perform net.http_post(
    url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/push-notify',
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', secret),
    body    := jsonb_build_object('mode', 'invoice-portal-status', 'invoice_id', new.id),
    timeout_milliseconds := 20000
  );
  return new;
exception when others then
  return new;   -- a letter that fails never blocks the decision
end $$;
revoke all on function public.invoices_portal_mail() from public, anon, authenticated;

drop trigger if exists invoices_portal_mail on public.invoices;
create trigger invoices_portal_mail after update of status on public.invoices
  for each row execute function public.invoices_portal_mail();

notify pgrst, 'reload schema';

-- ============================================================
-- Freelancerių sąskaitos (4)
--  * ext_mail_log – paskutinio laiško freelanceriui rezultatas (programoje matosi, ar išėjo)
--  * file_total / file_check – kokia suma rasta įkeltame sąskaitos faile (tikrina AI)
--  * fl_portal_sessions.scans – jau perskaitytų failų sumos (tas pats failas neskaitomas du kartus)
-- Reikia: freelance_portal.sql, freelance_portal3.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.invoices add column if not exists ext_mailed   text;
alter table public.invoices add column if not exists ext_mail_log jsonb;
alter table public.invoices add column if not exists file_total   numeric(12,2);
alter table public.invoices add column if not exists file_check   text;
alter table public.fl_portal_sessions add column if not exists scans jsonb not null default '{}'::jsonb;
notify pgrst, 'reload schema';

-- ============================================================
-- Sąskaitos iš el. pašto: saskaitos@eventsolutions.lt
--  * kiekvienas naujas laiškas į sąskaitų dėžutę tampa sąskaita „Sąskaitose“
--    (priedai – sąskaitos failai; suma randama PDF'e; tiekėjas – siuntėjas)
--  * rūšis parenkama pagal raktažodžius (Admin+ nustato: „📥 Sąskaitų dėžutė“);
--    nepritaikius jokios taisyklės – numatytoji rūšis (pvz. „Kitos“)
--  * invoice_inbox – dėžutės prisijungimas (slaptažodis užšifruotas), taisyklės, būsena;
--    pasiekiama tik per „mail“ funkciją
--  * invoices.mail_id – laiško Message-ID (tas pats laiškas neįkeliamas du kartus)
-- Reikia: invoices.sql. Funkcijos: mail (v28), push-notify.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- nauja rūšis „Kitos“ (nesurūšiuotos)
alter table public.invoices drop constraint if exists invoices_kind_check;
alter table public.invoices add constraint invoices_kind_check check (kind in ('freelance','service','rent','purchase','other'));

alter table public.invoices add column if not exists source    text;
alter table public.invoices add column if not exists ext_email text;
alter table public.invoices add column if not exists ext_name  text;
alter table public.invoices add column if not exists mail_id   text;
create unique index if not exists invoices_mail_id on public.invoices (mail_id) where mail_id is not null;

create table if not exists public.invoice_inbox (
  id            integer primary key default 1 check (id = 1),
  email         text,
  host          text,
  secret        text,
  active        boolean not null default false,
  rules         jsonb not null default '[]'::jsonb,   -- [{kw:"lemona, ignitis", where:"any|from|subject|text|file", kind, supplier}]
  default_kind  text not null default 'other',
  state         jsonb not null default '{}'::jsonb,
  updated_at    timestamptz not null default now()
);
alter table public.invoice_inbox enable row level security;
revoke all on public.invoice_inbox from anon, authenticated;

notify pgrst, 'reload schema';

-- ============================================================
-- Sąskaitų patikra ofise (Freelance sąskaitos)
--  * Office, Projektų vadovai (ir Admin) mato gautas sąskaitas (Freelance, iš portalo,
--    iš el. pašto), gali pakeisti rūšį, parašyti siuntėjui (viskas tvarkoje / reikia korekcijų)
--    ir pažymėti „Sąskaita patikrinta“
--  * Freelance sąskaita Admin+ „Naujose“ atsiranda tik patikrinta ofise
--  * checked_by / checked_at – kas ir kada patikrino; check_msgs – žinutės siuntėjui ir patikros istorija
-- Reikia: invoices.sql, invoice_inbox.sql. Funkcijos: push-notify, files, freelance-portal.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.invoices add column if not exists checked_by uuid references auth.users(id) on delete set null;
alter table public.invoices add column if not exists checked_at timestamptz;
alter table public.invoices add column if not exists check_msgs jsonb not null default '[]'::jsonb;   -- [{at, by, who, kind:'ok'|'fix'|'note'|'checked'|'kind', text, to}]

-- kas tikrina: Office, Projektų vadovas, Admin
create or replace function public.is_inv_checker() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role in ('office','pm','admin') from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.is_inv_checker() to authenticated;

-- kurios sąskaitos tikrinamos: Freelance ir gautos iš išorės (portalas, el. paštas)
create or replace function public.inv_checkable(k text, src text) returns boolean
  language sql immutable as $$ select k = 'freelance' or coalesce(src, '') in ('portal','email') $$;

drop policy if exists "invoices check read" on public.invoices;
create policy "invoices check read" on public.invoices
  for select to authenticated using (public.is_inv_checker() and public.inv_checkable(kind, source));

-- failai: tikrintojas mato tikrinamų sąskaitų failus
create or replace function public.inv_file_checkable(p_path text) returns boolean
  language sql stable security definer set search_path = public as $$
  select public.is_inv_checker() and exists (
    select 1 from public.invoices i
    where public.inv_checkable(i.kind, i.source) and i.files @> jsonb_build_array(jsonb_build_object('path', p_path)))
$$;
grant execute on function public.inv_file_checkable(text) to authenticated;
drop policy if exists "invoice files check view" on storage.objects;
create policy "invoice files check view" on storage.objects
  for select to authenticated using (bucket_id = 'invoice-files' and public.inv_file_checkable(name));

-- patikros veiksmai (tik per šią funkciją: tikrintojas kitų laukų keisti negali)
--   kind  – priskirti rūšį;  check – „Sąskaita patikrinta“ (tik Freelance);  uncheck – atšaukti;
--   note  – žinutė į istoriją (laiškas siuntėjui eina per push-notify)
create or replace function public.invoice_office(p_id uuid, p_action text, p_kind text default null, p_text text default null)
  returns public.invoices language plpgsql security definer set search_path = public as $$
declare v public.invoices; who text;
begin
  if not (public.is_inv_checker() or public.is_plus()) then raise exception 'Sąskaitas tikrina Office, Projektų vadovai ir Admin.'; end if;
  select * into v from public.invoices where id = p_id for update;
  if not found or not public.inv_checkable(v.kind, v.source) then raise exception 'Sąskaita nerasta.'; end if;
  if v.status not in ('new','later') and p_action <> 'note' then raise exception 'Sąskaita jau sutvarkyta (Admin+ sprendimas priimtas).'; end if;
  select coalesce(nullif(trim(coalesce(first_name,'')||' '||coalesce(last_name,'')),''), full_name, email) into who from public.profiles where id = auth.uid();
  if p_action = 'kind' then
    if p_kind not in ('freelance','service','rent','purchase','other') then raise exception 'Nežinoma rūšis.'; end if;
    update public.invoices set kind = p_kind,
      check_msgs = check_msgs || jsonb_build_array(jsonb_build_object('at', now(), 'by', auth.uid(), 'who', who, 'kind', 'kind', 'text', p_kind))
      where id = p_id returning * into v;
  elsif p_action = 'check' then
    if v.kind <> 'freelance' then raise exception 'Patikra reikalinga tik Freelance sąskaitoms.'; end if;
    update public.invoices set checked_at = now(), checked_by = auth.uid(),
      check_msgs = check_msgs || jsonb_build_array(jsonb_build_object('at', now(), 'by', auth.uid(), 'who', who, 'kind', 'checked', 'text', coalesce(p_text,'')))
      where id = p_id returning * into v;
  elsif p_action = 'uncheck' then
    update public.invoices set checked_at = null, checked_by = null,
      check_msgs = check_msgs || jsonb_build_array(jsonb_build_object('at', now(), 'by', auth.uid(), 'who', who, 'kind', 'unchecked', 'text', ''))
      where id = p_id returning * into v;
  elsif p_action = 'note' then
    update public.invoices set check_msgs = check_msgs || jsonb_build_array(jsonb_build_object('at', now(), 'by', auth.uid(), 'who', who, 'kind', 'note', 'text', left(coalesce(p_text,''), 2000)))
      where id = p_id returning * into v;
  else raise exception 'Nežinomas veiksmas.';
  end if;
  return v;
end $$;
grant execute on function public.invoice_office(uuid, text, text, text) to authenticated;

notify pgrst, 'reload schema';


-- ===== tracker_edit.sql =====
-- ============================================================
-- Team Tracker: darbo pradžios laiko pataisymas
--  * time_shifts.start_edits – pakeitimų žurnalas: [{from, to, note, loc, at, by}]
--    (loc – kur buvo telefonas, kai pradžia pakeista: {lat, lng, acc, addr} arba {err})
--  * tt_set_start(...) – vykstančios pamainos pradžią pakeičia pats narys (savo raktu);
--    ne vėlesnė nei pirmos veiklos pabaiga, ne ankstesnė nei ankstesnės pamainos pabaiga, ne senesnė nei 24 val.
--  * tt_shift_json – grąžina ir start_edits (rodoma suvestinėse ir Excel)
-- Reikia: tracker.sql, tracker_loc.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.time_shifts add column if not exists start_edits jsonb not null default '[]'::jsonb;

create or replace function public.tt_shift_json(sid uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', s.id, 'started_at', s.started_at, 'ended_at', s.ended_at,
    'start_loc', s.start_loc, 'end_loc', s.end_loc, 'start_edits', s.start_edits,
    'entries', coalesce((select jsonb_agg(jsonb_build_object('kind', e.kind, 'started_at', e.started_at, 'ended_at', e.ended_at) order by e.started_at)
                         from public.time_entries e where e.shift_id = s.id), '[]'::jsonb))
  from public.time_shifts s where s.id = sid
$$;

create or replace function public.tt_set_start(m uuid, p_token text, p_at timestamptz, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; fe public.time_entries; prev_end timestamptz; lim timestamptz; loc jsonb; nt text := left(btrim(coalesce(p_note, '')), 500);
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where member_id = m and ended_at is null;
  if s.id is null then return jsonb_build_object('error', 'Darbas nepradėtas.'); end if;
  if p_at is null then return jsonb_build_object('error', 'Nurodyk pradžios laiką.'); end if;
  p_at := date_trunc('minute', p_at);
  select * into fe from public.time_entries where shift_id = s.id order by started_at limit 1;
  lim := coalesce(fe.ended_at, now());
  if p_at > lim then
    return jsonb_build_object('error', case when fe.ended_at is null then 'Pradžia negali būti vėlesnė nei dabar.' else 'Pradžia negali būti vėlesnė nei pirmos veiklos pabaiga ('||to_char(fe.ended_at at time zone 'Europe/Vilnius', 'HH24:MI')||').' end);
  end if;
  if p_at < now() - interval '24 hours' then return jsonb_build_object('error', 'Pradžią galima paankstinti ne daugiau kaip 24 val.'); end if;
  select max(ended_at) into prev_end from public.time_shifts where member_id = m and id <> s.id and ended_at is not null;
  if prev_end is not null and p_at < prev_end then
    return jsonb_build_object('error', 'Pradžia negali būti ankstesnė nei ankstesnės pamainos pabaiga ('||to_char(prev_end at time zone 'Europe/Vilnius', 'YYYY-MM-DD HH24:MI')||').');
  end if;
  if p_at = s.started_at then return public.tt_state_of(m); end if;
  loc := jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20)));
  update public.time_entries set started_at = p_at where id = fe.id;
  update public.time_shifts set started_at = p_at,
    start_edits = coalesce(start_edits, '[]'::jsonb) || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
      'from', s.started_at, 'to', p_at, 'note', nullif(nt, ''), 'loc', case when loc = '{}'::jsonb then null else loc end, 'at', now(), 'by', auth.uid())))
  where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_set_start(uuid, text, timestamptz, text, jsonb) from public, anon;
grant execute on function public.tt_set_start(uuid, text, timestamptz, text, jsonb) to authenticated;

notify pgrst, 'reload schema';


-- ===== report_reminders.sql =====
-- ============================================================
-- Uta / Wolt / Bolt ataskaitų priminimai
--  * report_reminders – kam priminti (įrašytas el. paštas ARBA programėlės narys), kokiu periodu
--    (kas savaitę / mėnesį / ketvirtį), kurią dieną terminas, kiek dienų prieš pradėti ir kiek kartų priminti
--    (pirmas – „days_before“ d. prieš terminą, toliau kas dieną, iš viso „times“ kartų, ne vėliau nei termino dieną)
--  * siunčia push-notify (jau veikiantis kas 5 min. darbas) apie 8 val. ryto; narys gauna pranešimą ir laišką,
--    įrašytas el. paštas – laišką (RESEND_API_KEY). Mėnesio priminimas nesiunčiamas, jei praėjusio mėnesio ataskaita jau įkelta.
--  * tvarko Admin ir Office
-- Reikia: office_bolt.sql, uta.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.report_reminders (
  id           uuid primary key default gen_random_uuid(),
  kind         text not null check (kind in ('uta','wolt','bolt')),
  to_email     text check (to_email is null or to_email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  to_user      uuid references auth.users(id) on delete cascade,
  period       text not null default 'month' check (period in ('week','month','quarter')),
  due_day      integer not null default 5 check (due_day between 1 and 28),
  days_before  integer not null default 3 check (days_before between 0 and 60),
  times        integer not null default 1 check (times between 1 and 10),
  note         text,
  active       boolean not null default true,
  sent         jsonb not null default '{}'::jsonb,
  created_by   uuid default auth.uid(),
  created_at   timestamptz not null default now(),
  constraint report_reminders_to check (to_email is not null or to_user is not null)
);
create index if not exists report_reminders_kind on public.report_reminders (kind);

alter table public.report_reminders enable row level security;
drop policy if exists "report reminders office" on public.report_reminders;
create policy "report reminders office" on public.report_reminders for all to authenticated
  using (public.office_admin()) with check (public.office_admin());
grant select, insert, update, delete on public.report_reminders to authenticated;

notify pgrst, 'reload schema';


-- ===== vehicle_kasko.sql =====
-- ============================================================
-- Transportas: KASKO draudimo galiojimas (šalia draudimo, tech. apžiūros ir kelių mokesčio)
--  * vehicle_reminders.kasko_until – priminimai el. paštu kaip ir kitiems dokumentams (funkcija vehicle-reminders)
--  * KASKO nebūtinas: jei data neįrašyta, apie jį neprimenama
-- Reikia: vehicle_reminders.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.vehicle_reminders add column if not exists kasko_until date;
notify pgrst, 'reload schema';


-- ===== vehicle_incident.sql =====
-- ============================================================
-- Transportas: „Registruoti įvykį“ (avarija, apgadinimas, bauda ir pan.)
--  * vehicle_logs.kind 'incident' – data, laikas (data.time), kas nutiko, aprašymas, komentaras (data.comment),
--    vieta (data.loc), nuotraukos ir video (files, saugykla 'fleet-files')
--  * įregistruoti gali kiekvienas, kas mato „Transportą“ (kaip problemą ar profilaktiką); taisyti – pats ir tie, kas redaguoja „Transportą“
-- Reikia: vehicle_logs.sql, vehicle_logs2.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.vehicle_logs drop constraint if exists vehicle_logs_kind_check;
alter table public.vehicle_logs add constraint vehicle_logs_kind_check check (kind in ('service','problem','check','incident'));

drop policy if exists "fleet logs add" on public.vehicle_logs;
create policy "fleet logs add" on public.vehicle_logs for insert to authenticated
  with check (public.can_view('fleet') and created_by = auth.uid() and (kind in ('problem','check','incident') or public.can_edit('fleet')));
drop policy if exists "fleet logs change" on public.vehicle_logs;
create policy "fleet logs change" on public.vehicle_logs for update to authenticated
  using (public.can_edit('fleet') or created_by = auth.uid())
  with check (public.can_edit('fleet') or (created_by = auth.uid() and kind in ('problem','check','incident')));

notify pgrst, 'reload schema';


-- ===== tracker_edit2.sql =====
-- ============================================================
-- Team Tracker: jau baigtos pamainos pradžios ir pabaigos taisymas
--  * tt_edit_shift(...) – narys (savo raktu) pataiso savo baigtos pamainos pradžią ir / ar pabaigą
--    (ne senesnės nei 30 d.; pamainos negali persidengti; pradžia – prieš pabaigą; pabaiga – ne vėliau nei dabar)
--  * pakeitimas įrašomas į time_shifts.start_edits: {from, to} – pradžia, {end_from, end_to} – pabaiga,
--    komentaras, vieta, kada ir kas pakeitė (rodoma suvestinėse ir Excel)
-- Reikia: tracker_edit.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.tt_edit_shift(m uuid, p_token text, p_shift uuid, p_start timestamptz, p_end timestamptz, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; fe public.time_entries; le public.time_entries; n int; loc jsonb; ed jsonb;
        nt text := left(btrim(coalesce(p_note, '')), 500); vs text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where id = p_shift and member_id = m;
  if s.id is null then return jsonb_build_object('error', 'Tokios pamainos nėra.'); end if;
  if s.ended_at is null then return jsonb_build_object('error', 'Pamaina dar vyksta – pradžią taisyk per „✎ Pataisyti“.'); end if;
  if s.started_at < now() - interval '30 days' then return jsonb_build_object('error', 'Taisyti galima tik pastarųjų 30 d. pamainas.'); end if;
  if p_start is null or p_end is null then return jsonb_build_object('error', 'Nurodyk pradžios ir pabaigos laiką.'); end if;
  p_start := date_trunc('minute', p_start); p_end := date_trunc('minute', p_end);
  if p_end <= p_start then return jsonb_build_object('error', 'Pabaiga turi būti vėlesnė nei pradžia.'); end if;
  if p_end > now() then return jsonb_build_object('error', 'Pabaiga negali būti vėlesnė nei dabar.'); end if;
  if p_end - p_start > interval '36 hours' then return jsonb_build_object('error', 'Pamaina negali būti ilgesnė nei 36 val.'); end if;
  if exists (select 1 from public.time_shifts o where o.member_id = m and o.id <> s.id
             and o.started_at < p_end and coalesce(o.ended_at, now()) > p_start) then
    return jsonb_build_object('error', 'Šis laikas persidengia su kita tavo pamaina.');
  end if;
  select count(*) into n from public.time_entries where shift_id = s.id;
  select * into fe from public.time_entries where shift_id = s.id order by started_at limit 1;
  select * into le from public.time_entries where shift_id = s.id order by started_at desc limit 1;
  if n > 1 then
    if p_start >= fe.ended_at then
      return jsonb_build_object('error', 'Pradžia negali būti vėlesnė nei pirmos veiklos pabaiga ('||to_char(fe.ended_at at time zone 'Europe/Vilnius', 'HH24:MI')||').');
    end if;
    if p_end <= le.started_at then
      return jsonb_build_object('error', 'Pabaiga negali būti ankstesnė nei paskutinės veiklos pradžia ('||to_char(le.started_at at time zone 'Europe/Vilnius', 'HH24:MI')||').');
    end if;
  end if;
  if p_start = s.started_at and p_end = s.ended_at then return public.tt_state_of(m); end if;
  loc := jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20)));
  ed := jsonb_strip_nulls(jsonb_build_object(
    'from', case when p_start <> s.started_at then s.started_at end, 'to', case when p_start <> s.started_at then p_start end,
    'end_from', case when p_end <> s.ended_at then s.ended_at end, 'end_to', case when p_end <> s.ended_at then p_end end,
    'note', nullif(nt, ''), 'loc', case when loc = '{}'::jsonb then null else loc end, 'at', now(), 'by', auth.uid()));
  update public.time_entries set started_at = p_start where id = fe.id;
  update public.time_entries set ended_at = p_end where id = le.id;
  update public.time_shifts set started_at = p_start, ended_at = p_end,
    start_edits = coalesce(start_edits, '[]'::jsonb) || jsonb_build_array(ed)
  where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_edit_shift(uuid, text, uuid, timestamptz, timestamptz, text, jsonb) from public, anon;
grant execute on function public.tt_edit_shift(uuid, text, uuid, timestamptz, timestamptz, text, jsonb) to authenticated;

notify pgrst, 'reload schema';


-- ===== chat_pins.sql =====
-- ============================================================
-- Chatas: prisegtos žinutės (📌) – visada rodomos pokalbio viršuje
--  * messages.pinned_at / pinned_by – kada ir kas prisegė
--  * chat_pin(p_mid, p_on) – prisegti / atsegti gali kiekvienas pokalbio narys
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.messages add column if not exists pinned_at timestamptz;
alter table public.messages add column if not exists pinned_by uuid references auth.users(id) on delete set null;
create index if not exists messages_pinned on public.messages (conversation_id, pinned_at) where pinned_at is not null;

create or replace function public.chat_pin(p_mid uuid, p_on boolean) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare m public.messages;
begin
  select * into m from public.messages where id = p_mid;
  if m.id is null then return jsonb_build_object('error', 'Žinutės nėra.'); end if;
  if not public.is_conv_member(m.conversation_id) then return jsonb_build_object('error', 'Nesi šio pokalbio narys.'); end if;
  update public.messages set pinned_at = case when p_on then now() end, pinned_by = case when p_on then auth.uid() end
    where id = p_mid returning * into m;
  return to_jsonb(m);
end $$;
revoke all on function public.chat_pin(uuid, boolean) from public, anon;
grant execute on function public.chat_pin(uuid, boolean) to authenticated;

notify pgrst, 'reload schema';


-- ===== app_release.sql =====
-- ============================================================
-- Atnaujinimų išleidimas: nauja programėlės versija pirma rodoma tik Super Admin,
-- kitiems – tik kai Super Admin „Atnaujinimuose“ paspaudžia „Išleisti visiems“
--  * app_release (viena eilutė) – kuri versija išleista visiems (skaito visi, net neprisijungę – programėlės darbuotojas)
--  * app_release_set(p_version) – išleisti gali tik Super Admin (profiles.level = 'super')
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.app_release (
  id            int primary key default 1 check (id = 1),
  version       text not null check (version ~ '^v[0-9]+$'),
  released_at   timestamptz not null default now(),
  released_by   uuid,
  released_name text
);
-- pradžia: dabartinė versija jau išleista visiems
insert into public.app_release (id, version) values (1, 'v448') on conflict (id) do nothing;

alter table public.app_release enable row level security;
drop policy if exists "app release read" on public.app_release;
create policy "app release read" on public.app_release for select to anon, authenticated using (true);
grant select on public.app_release to anon, authenticated;
revoke insert, update, delete on public.app_release from anon, authenticated;

create or replace function public.app_release_set(p_version text) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare me public.profiles; cur text;
begin
  select * into me from public.profiles where id = auth.uid();
  if me.id is null or coalesce(me.level, '') <> 'super' then return jsonb_build_object('error', 'Išleisti gali tik Super Admin.'); end if;
  if coalesce(p_version, '') !~ '^v[0-9]+$' then return jsonb_build_object('error', 'Neteisinga versija.'); end if;
  select version into cur from public.app_release where id = 1;
  if cur is not null and substring(cur from 2)::int >= substring(p_version from 2)::int then
    return jsonb_build_object('error', 'Versija '||p_version||' jau išleista (visiems – '||cur||').');
  end if;
  insert into public.app_release (id, version, released_at, released_by, released_name)
    values (1, p_version, now(), me.id, nullif(btrim(coalesce(me.first_name, '')||' '||coalesce(me.last_name, '')), ''))
    on conflict (id) do update set version = excluded.version, released_at = excluded.released_at,
      released_by = excluded.released_by, released_name = excluded.released_name;
  return (select to_jsonb(r) from public.app_release r where id = 1);
end $$;
revoke all on function public.app_release_set(text) from public, anon;
grant execute on function public.app_release_set(text) to authenticated;

notify pgrst, 'reload schema';

-- ============================================================
-- Team Tracker: komentaras būtinas keičiant pradžios / pabaigos laiką
--  * tt_set_start ir tt_edit_shift atmeta pakeitimą be komentaro (bent 3 simboliai)
--  * tt_edit_shift: keičiant tik pradžią arba tik pabaigą, kitas laikas lieka tiksliai toks, koks buvo
--    (nebeapvalinamas iki minutės ir nebeįrašomas į žurnalą kaip pakeistas)
-- Reikia: tracker_edit.sql, tracker_edit2.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.tt_set_start(m uuid, p_token text, p_at timestamptz, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; fe public.time_entries; prev_end timestamptz; lim timestamptz; loc jsonb; nt text := left(btrim(coalesce(p_note, '')), 500);
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where member_id = m and ended_at is null;
  if s.id is null then return jsonb_build_object('error', 'Darbas nepradėtas.'); end if;
  if p_at is null then return jsonb_build_object('error', 'Nurodyk pradžios laiką.'); end if;
  if char_length(nt) < 3 then return jsonb_build_object('error', 'Parašyk komentarą – kodėl keiti laiką.'); end if;
  p_at := date_trunc('minute', p_at);
  select * into fe from public.time_entries where shift_id = s.id order by started_at limit 1;
  lim := coalesce(fe.ended_at, now());
  if p_at > lim then
    return jsonb_build_object('error', case when fe.ended_at is null then 'Pradžia negali būti vėlesnė nei dabar.' else 'Pradžia negali būti vėlesnė nei pirmos veiklos pabaiga ('||to_char(fe.ended_at at time zone 'Europe/Vilnius', 'HH24:MI')||').' end);
  end if;
  if p_at < now() - interval '24 hours' then return jsonb_build_object('error', 'Pradžią galima paankstinti ne daugiau kaip 24 val.'); end if;
  select max(ended_at) into prev_end from public.time_shifts where member_id = m and id <> s.id and ended_at is not null;
  if prev_end is not null and p_at < prev_end then
    return jsonb_build_object('error', 'Pradžia negali būti ankstesnė nei ankstesnės pamainos pabaiga ('||to_char(prev_end at time zone 'Europe/Vilnius', 'YYYY-MM-DD HH24:MI')||').');
  end if;
  if p_at = s.started_at then return public.tt_state_of(m); end if;
  loc := jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20)));
  update public.time_entries set started_at = p_at where id = fe.id;
  update public.time_shifts set started_at = p_at,
    start_edits = coalesce(start_edits, '[]'::jsonb) || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
      'from', s.started_at, 'to', p_at, 'note', nullif(nt, ''), 'loc', case when loc = '{}'::jsonb then null else loc end, 'at', now(), 'by', auth.uid())))
  where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_set_start(uuid, text, timestamptz, text, jsonb) from public, anon;
grant execute on function public.tt_set_start(uuid, text, timestamptz, text, jsonb) to authenticated;


create or replace function public.tt_edit_shift(m uuid, p_token text, p_shift uuid, p_start timestamptz, p_end timestamptz, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; fe public.time_entries; le public.time_entries; n int; loc jsonb; ed jsonb;
        nt text := left(btrim(coalesce(p_note, '')), 500); vs text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where id = p_shift and member_id = m;
  if s.id is null then return jsonb_build_object('error', 'Tokios pamainos nėra.'); end if;
  if s.ended_at is null then return jsonb_build_object('error', 'Pamaina dar vyksta – pradžią keisk per „✎ Pakeisti pradžios laiką“.'); end if;
  if s.started_at < now() - interval '30 days' then return jsonb_build_object('error', 'Taisyti galima tik pastarųjų 30 d. pamainas.'); end if;
  if p_start is null or p_end is null then return jsonb_build_object('error', 'Nurodyk pradžios ir pabaigos laiką.'); end if;
  if char_length(nt) < 3 then return jsonb_build_object('error', 'Parašyk komentarą – kodėl keiti laiką.'); end if;
  -- the app sends times to the millisecond, the database keeps microseconds: a time within 1 ms of the saved one is not changed
  if abs(extract(epoch from p_start - s.started_at)) < 0.001 then p_start := s.started_at; end if;
  if abs(extract(epoch from p_end - s.ended_at)) < 0.001 then p_end := s.ended_at; end if;
  -- only a time that is really changed is rounded to the minute (the other one stays exactly as it was)
  if p_start <> s.started_at then p_start := date_trunc('minute', p_start); end if;
  if p_end <> s.ended_at then p_end := date_trunc('minute', p_end); end if;
  if p_end <= p_start then return jsonb_build_object('error', 'Pabaiga turi būti vėlesnė nei pradžia.'); end if;
  if p_end > now() then return jsonb_build_object('error', 'Pabaiga negali būti vėlesnė nei dabar.'); end if;
  if p_end - p_start > interval '36 hours' then return jsonb_build_object('error', 'Pamaina negali būti ilgesnė nei 36 val.'); end if;
  select string_agg(to_char(o.started_at at time zone 'Europe/Vilnius', 'MM-DD HH24:MI')||' – '||coalesce(to_char(o.ended_at at time zone 'Europe/Vilnius', 'HH24:MI'), 'vyksta'), ', ' order by o.started_at)
    into vs from public.time_shifts o where o.member_id = m and o.id <> s.id
             and o.started_at < p_end and coalesce(o.ended_at, now()) > p_start;
  if vs is not null then
    return jsonb_build_object('error', 'Šis laikas persidengia su kita tavo pamaina: '||vs||'. Pirma pataisyk tą pamainą.');
  end if;
  select count(*) into n from public.time_entries where shift_id = s.id;
  select * into fe from public.time_entries where shift_id = s.id order by started_at limit 1;
  select * into le from public.time_entries where shift_id = s.id order by started_at desc limit 1;
  -- only the time that is changed is checked against the activities (the other one stays as it was)
  if n > 1 then
    if p_start <> s.started_at and p_start >= fe.ended_at then
      return jsonb_build_object('error', 'Pradžia negali būti vėlesnė nei pirmos veiklos pabaiga ('||to_char(fe.ended_at at time zone 'Europe/Vilnius', 'HH24:MI')||').');
    end if;
    if p_end <> s.ended_at and p_end <= le.started_at then
      return jsonb_build_object('error', 'Pabaiga negali būti ankstesnė nei paskutinės veiklos pradžia ('||to_char(le.started_at at time zone 'Europe/Vilnius', 'HH24:MI')||').');
    end if;
  end if;
  if p_start = s.started_at and p_end = s.ended_at then return public.tt_state_of(m); end if;
  loc := jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20)));
  ed := jsonb_strip_nulls(jsonb_build_object(
    'from', case when p_start <> s.started_at then s.started_at end, 'to', case when p_start <> s.started_at then p_start end,
    'end_from', case when p_end <> s.ended_at then s.ended_at end, 'end_to', case when p_end <> s.ended_at then p_end end,
    'note', nullif(nt, ''), 'loc', case when loc = '{}'::jsonb then null else loc end, 'at', now(), 'by', auth.uid()));
  update public.time_entries set started_at = p_start where id = fe.id;
  update public.time_entries set ended_at = p_end where id = le.id;
  update public.time_shifts set started_at = p_start, ended_at = p_end,
    start_edits = coalesce(start_edits, '[]'::jsonb) || jsonb_build_array(ed)
  where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_edit_shift(uuid, text, uuid, timestamptz, timestamptz, text, jsonb) from public, anon;
grant execute on function public.tt_edit_shift(uuid, text, uuid, timestamptz, timestamptz, text, jsonb) to authenticated;


notify pgrst, 'reload schema';

-- ============================================================
-- Team Tracker: savo pamainos ištrynimas
--  * tt_delete_shift(...) – narys (savo raktu) ištrina savo BAIGTĄ pamainą (ne senesnę nei 30 d.);
--    komentaras būtinas, užfiksuojama vieta
--  * ištrinta pamaina (su visomis veiklomis), komentaras, vieta, kada ir kas – lieka žurnale time_shift_deletions
--  * tt_report grąžina ir to laikotarpio ištrintas pamainas ('deleted') – vadovai mato, kas ištrinta ir kodėl
-- Reikia: tracker.sql, tracker_edit.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.time_shift_deletions (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references public.tracker_members(id) on delete cascade,
  shift jsonb not null,
  note text not null,
  loc jsonb,
  at timestamptz not null default now(),
  by uuid
);
create index if not exists time_shift_deletions_member on public.time_shift_deletions(member_id, at);
alter table public.time_shift_deletions enable row level security;   -- read only through tt_report

create or replace function public.tt_delete_shift(m uuid, p_token text, p_shift uuid, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; loc jsonb; nt text := left(btrim(coalesce(p_note, '')), 500);
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where id = p_shift and member_id = m;
  if s.id is null then return jsonb_build_object('error', 'Tokios pamainos nėra.'); end if;
  if s.ended_at is null then return jsonb_build_object('error', 'Vykstančios pamainos ištrinti negalima – pirma baik darbą.'); end if;
  if s.started_at < now() - interval '30 days' then return jsonb_build_object('error', 'Ištrinti galima tik pastarųjų 30 d. pamainas.'); end if;
  if char_length(nt) < 3 then return jsonb_build_object('error', 'Parašyk komentarą – kodėl trini pamainą.'); end if;
  loc := jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20)));
  insert into public.time_shift_deletions(member_id, shift, note, loc, by)
    values (m, public.tt_shift_json(s.id), nt, case when loc = '{}'::jsonb then null else loc end, auth.uid());
  delete from public.time_entries where shift_id = s.id;
  delete from public.time_shifts where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_delete_shift(uuid, text, uuid, text, jsonb) from public, anon;
grant execute on function public.tt_delete_shift(uuid, text, uuid, text, jsonb) to authenticated;

create or replace function public.tt_report(m uuid, p_token text, p_from timestamptz, p_to timestamptz) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, true);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shifts', coalesce((select jsonb_agg(public.tt_shift_json(s.id) order by s.started_at desc) from public.time_shifts s
       where s.member_id = m and s.started_at < p_to and coalesce(s.ended_at, now()) > p_from), '[]'::jsonb),
    'deleted', coalesce((select jsonb_agg(jsonb_build_object('shift', d.shift, 'note', d.note, 'loc', d.loc, 'at', d.at) order by d.at desc)
       from public.time_shift_deletions d
       where d.member_id = m and (d.shift->>'started_at')::timestamptz < p_to and coalesce((d.shift->>'ended_at')::timestamptz, d.at) > p_from), '[]'::jsonb));
end $$;

notify pgrst, 'reload schema';

-- ============================================================
-- Team Tracker: laisvas pradžios / pabaigos keitimas, komentaras būtinas
--  * tt_set_start (vykstanti pamaina) ir tt_edit_shift (baigta pamaina): laiką galima keisti kaip nori,
--    būtinas tik komentaras (bent 3 simboliai); lieka tik: pabaiga po pradžios, ne ateityje,
--    ir pamaina neuždengia kitos tavo pamainos (klaida nurodo, kurios)
--  * veiklos prisitaiko: pirma prasideda nuo naujos pradžios, paskutinė baigiasi naujos pabaigos metu,
--    veiklos už naujų ribų nukerpamos (jei nelieka nė vienos – lieka viena per visą pamainą)
--  * keičiant tik pradžią ar tik pabaigą, kitas laikas lieka toks, koks buvo (< 1 ms skirtumas – nepakeista)
--  * kiekvienas pakeitimas su komentaru, vieta, kada ir kas – žurnale time_shifts.start_edits
-- Reikia: tracker_edit.sql, tracker_edit2.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- the place where the change was made, cleaned up
create or replace function public.tt_loc_clean(p_loc jsonb) returns jsonb
  language sql immutable as $$
  select nullif(jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20))), '{}'::jsonb)
$$;

-- the other shifts of the member that a time span would cover (empty – none)
create or replace function public.tt_overlaps(m uuid, sid uuid, a timestamptz, z timestamptz) returns text
  language sql stable security definer set search_path = public as $$
  select string_agg(to_char(o.started_at at time zone 'Europe/Vilnius', 'MM-DD HH24:MI')||' – '||coalesce(to_char(o.ended_at at time zone 'Europe/Vilnius', 'HH24:MI'), 'vyksta'), ', ' order by o.started_at)
  from public.time_shifts o where o.member_id = m and o.id <> sid and o.started_at < z and coalesce(o.ended_at, now()) > a
$$;

-- the activities follow the shift's new bounds
create or replace function public.tt_fit_entries(sid uuid, a timestamptz, z timestamptz, kind0 text) returns void
  language plpgsql security definer set search_path = public as $$
declare fid uuid; lid uuid;
begin
  -- what is wholly outside the new span goes (the running activity – ended_at null – stays while the shift runs)
  delete from public.time_entries where shift_id = sid and ((ended_at is not null and ended_at <= a) or (z is not null and started_at >= z));
  if not exists (select 1 from public.time_entries where shift_id = sid) then
    insert into public.time_entries(shift_id, kind, started_at, ended_at) values (sid, coalesce(kind0, 'warehouse'), a, z);
    return;
  end if;
  select id into fid from public.time_entries where shift_id = sid order by started_at limit 1;
  update public.time_entries set started_at = a where id = fid;
  if z is not null then
    select id into lid from public.time_entries where shift_id = sid order by started_at desc limit 1;
    update public.time_entries set ended_at = z where id = lid;
  end if;
end $$;
revoke all on function public.tt_overlaps(uuid, uuid, timestamptz, timestamptz), public.tt_fit_entries(uuid, timestamptz, timestamptz, text) from public, anon, authenticated;

create or replace function public.tt_set_start(m uuid, p_token text, p_at timestamptz, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; k0 text; vs text; nt text := left(btrim(coalesce(p_note, '')), 500);
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where member_id = m and ended_at is null;
  if s.id is null then return jsonb_build_object('error', 'Darbas nepradėtas.'); end if;
  if p_at is null then return jsonb_build_object('error', 'Nurodyk pradžios laiką.'); end if;
  if char_length(nt) < 3 then return jsonb_build_object('error', 'Parašyk komentarą – kodėl keiti laiką.'); end if;
  if abs(extract(epoch from p_at - s.started_at)) < 0.001 then return public.tt_state_of(m); end if;
  p_at := date_trunc('minute', p_at);
  if p_at > now() then return jsonb_build_object('error', 'Pradžia negali būti vėlesnė nei dabar.'); end if;
  vs := public.tt_overlaps(m, s.id, p_at, now());
  if vs is not null then return jsonb_build_object('error', 'Šis laikas persidengia su kita tavo pamaina: '||vs||'. Pirma pataisyk ar ištrink tą pamainą.'); end if;
  select kind into k0 from public.time_entries where shift_id = s.id order by started_at limit 1;
  perform public.tt_fit_entries(s.id, p_at, null, k0);
  update public.time_shifts set started_at = p_at,
    start_edits = coalesce(start_edits, '[]'::jsonb) || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
      'from', s.started_at, 'to', p_at, 'note', nt, 'loc', public.tt_loc_clean(p_loc), 'at', now(), 'by', auth.uid())))
  where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_set_start(uuid, text, timestamptz, text, jsonb) from public, anon;
grant execute on function public.tt_set_start(uuid, text, timestamptz, text, jsonb) to authenticated;

create or replace function public.tt_edit_shift(m uuid, p_token text, p_shift uuid, p_start timestamptz, p_end timestamptz, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; k0 text; vs text; nt text := left(btrim(coalesce(p_note, '')), 500);
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where id = p_shift and member_id = m;
  if s.id is null then return jsonb_build_object('error', 'Tokios pamainos nėra.'); end if;
  if s.ended_at is null then return jsonb_build_object('error', 'Pamaina dar vyksta – pradžią keisk per „✎ Pakeisti pradžios laiką“.'); end if;
  if p_start is null or p_end is null then return jsonb_build_object('error', 'Nurodyk pradžios ir pabaigos laiką.'); end if;
  if char_length(nt) < 3 then return jsonb_build_object('error', 'Parašyk komentarą – kodėl keiti laiką.'); end if;
  -- what is not changed stays exactly as it was (the app sends milliseconds, the database keeps microseconds)
  if abs(extract(epoch from p_start - s.started_at)) < 0.001 then p_start := s.started_at; else p_start := date_trunc('minute', p_start); end if;
  if abs(extract(epoch from p_end - s.ended_at)) < 0.001 then p_end := s.ended_at; else p_end := date_trunc('minute', p_end); end if;
  if p_start = s.started_at and p_end = s.ended_at then return public.tt_state_of(m); end if;
  if p_end <= p_start then return jsonb_build_object('error', 'Pabaiga turi būti vėlesnė nei pradžia.'); end if;
  if p_end > now() then return jsonb_build_object('error', 'Pabaiga negali būti vėlesnė nei dabar.'); end if;
  vs := public.tt_overlaps(m, s.id, p_start, p_end);
  if vs is not null then return jsonb_build_object('error', 'Šis laikas persidengia su kita tavo pamaina: '||vs||'. Pirma pataisyk ar ištrink tą pamainą.'); end if;
  select kind into k0 from public.time_entries where shift_id = s.id order by started_at limit 1;
  perform public.tt_fit_entries(s.id, p_start, p_end, k0);
  update public.time_shifts set started_at = p_start, ended_at = p_end,
    start_edits = coalesce(start_edits, '[]'::jsonb) || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
      'from', case when p_start <> s.started_at then s.started_at end, 'to', case when p_start <> s.started_at then p_start end,
      'end_from', case when p_end <> s.ended_at then s.ended_at end, 'end_to', case when p_end <> s.ended_at then p_end end,
      'note', nt, 'loc', public.tt_loc_clean(p_loc), 'at', now(), 'by', auth.uid())))
  where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_edit_shift(uuid, text, uuid, timestamptz, timestamptz, text, jsonb) from public, anon;
grant execute on function public.tt_edit_shift(uuid, text, uuid, timestamptz, timestamptz, text, jsonb) to authenticated;

notify pgrst, 'reload schema';

-- ============================================================
-- Team Tracker: savo pamainos ištrynimas
--  * tt_delete_shift(...) – narys (savo raktu) ištrina savo BAIGTĄ pamainą;
--    komentaras būtinas, užfiksuojama vieta
--  * ištrinta pamaina (su visomis veiklomis), komentaras, vieta, kada ir kas – lieka žurnale time_shift_deletions
--  * tt_report grąžina ir to laikotarpio ištrintas pamainas ('deleted') – vadovai mato, kas ištrinta ir kodėl
-- Reikia: tracker.sql, tracker_edit.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.time_shift_deletions (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references public.tracker_members(id) on delete cascade,
  shift jsonb not null,
  note text not null,
  loc jsonb,
  at timestamptz not null default now(),
  by uuid
);
create index if not exists time_shift_deletions_member on public.time_shift_deletions(member_id, at);
alter table public.time_shift_deletions enable row level security;   -- read only through tt_report

create or replace function public.tt_delete_shift(m uuid, p_token text, p_shift uuid, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; loc jsonb; nt text := left(btrim(coalesce(p_note, '')), 500);
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where id = p_shift and member_id = m;
  if s.id is null then return jsonb_build_object('error', 'Tokios pamainos nėra.'); end if;
  if s.ended_at is null then return jsonb_build_object('error', 'Vykstančios pamainos ištrinti negalima – pirma baik darbą.'); end if;
  if char_length(nt) < 3 then return jsonb_build_object('error', 'Parašyk komentarą – kodėl trini pamainą.'); end if;
  loc := jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20)));
  insert into public.time_shift_deletions(member_id, shift, note, loc, by)
    values (m, public.tt_shift_json(s.id), nt, case when loc = '{}'::jsonb then null else loc end, auth.uid());
  delete from public.time_entries where shift_id = s.id;
  delete from public.time_shifts where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_delete_shift(uuid, text, uuid, text, jsonb) from public, anon;
grant execute on function public.tt_delete_shift(uuid, text, uuid, text, jsonb) to authenticated;

create or replace function public.tt_report(m uuid, p_token text, p_from timestamptz, p_to timestamptz) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, true);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shifts', coalesce((select jsonb_agg(public.tt_shift_json(s.id) order by s.started_at desc) from public.time_shifts s
       where s.member_id = m and s.started_at < p_to and coalesce(s.ended_at, now()) > p_from), '[]'::jsonb),
    'deleted', coalesce((select jsonb_agg(jsonb_build_object('shift', d.shift, 'note', d.note, 'loc', d.loc, 'at', d.at) order by d.at desc)
       from public.time_shift_deletions d
       where d.member_id = m and (d.shift->>'started_at')::timestamptz < p_to and coalesce((d.shift->>'ended_at')::timestamptz, d.at) > p_from), '[]'::jsonb));
end $$;

notify pgrst, 'reload schema';

-- ============================================================
-- „Išlaidos“ ir UTA: taisyklės
--  * expense_allowance.unit – nario balansas asmeniniams pylimams: 'eur' arba 'l' (kas mėnesį pridedama,
--    nepanaudotas likutis pereina į kitą mėnesį); balansą priskiria Admin+ narys
--  * uta_personal.receipts / note – asmeninis UTA pylimas pagrindžiamas kvitu (nuotrauka) ir, jei reikia, komentaru
--  * exp_month_open(d) – mėnesio išlaidas ir pylimų pagrindimus narys pateikia / taiso iki kito mėnesio 10 d.
--    (pvz. už spalį – iki lapkričio 10 d. imtinai, Lietuvos laiku); Admin+ – visada
--  * išlaidą patvirtinti / atmesti ir kompensaciją (€ arba l) priskirti gali tik Admin+ narys
-- Reikia: expenses.sql, expense_allowance.sql, expenses_liters.sql, invoices.sql (is_plus).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.is_plus() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'admin' and level in ('plus','super') from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.is_plus() to authenticated;

-- the month of day d can still be filled in by the member: until the 10th of the next month (Vilnius time)
create or replace function public.exp_month_open(d date) returns boolean
  language sql stable as $$
  select d is not null and (now() at time zone 'Europe/Vilnius')::date <= (date_trunc('month', d) + interval '1 month' + interval '9 days')::date
$$;
grant execute on function public.exp_month_open(date) to authenticated;
create or replace function public.exp_tx_open(tx uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select public.exp_month_open((select tx_date from public.uta_tx where id = tx))
$$;
grant execute on function public.exp_tx_open(uuid) to authenticated;

-- the balance for personal fills: euros or litres
alter table public.expense_allowance add column if not exists unit text not null default 'eur';
alter table public.expense_allowance drop constraint if exists expense_allowance_unit_check;
alter table public.expense_allowance add constraint expense_allowance_unit_check check (unit in ('eur','l'));
drop policy if exists "allowance set" on public.expense_allowance;
create policy "allowance set" on public.expense_allowance for all to authenticated
  using (public.is_plus()) with check (public.is_plus());

-- a personal fill: its receipt and a note
alter table public.uta_personal add column if not exists receipts jsonb not null default '[]'::jsonb;
alter table public.uta_personal add column if not exists note text not null default '';
drop policy if exists "uta personal add" on public.uta_personal;
create policy "uta personal add" on public.uta_personal for insert to authenticated
  with check (public.is_plus() or (user_id = auth.uid() and public.uta_tx_mine(tx_id) and public.exp_tx_open(tx_id)));
drop policy if exists "uta personal edit" on public.uta_personal;
create policy "uta personal edit" on public.uta_personal for update to authenticated
  using (public.is_plus() or (user_id = auth.uid() and public.exp_tx_open(tx_id)))
  with check (public.is_plus() or (user_id = auth.uid() and public.exp_tx_open(tx_id)));
drop policy if exists "uta personal remove" on public.uta_personal;
create policy "uta personal remove" on public.uta_personal for delete to authenticated
  using (public.is_plus() or (user_id = auth.uid() and public.exp_tx_open(tx_id)));
grant update on public.uta_personal to authenticated;

-- the member's own expenses: only while the month is open
drop policy if exists "expenses add" on public.expenses;
create policy "expenses add" on public.expenses for insert to authenticated
  with check (user_id = auth.uid() and public.is_approved() and status = 'new' and comp is null and public.exp_month_open(spent_on));
drop policy if exists "expenses edit" on public.expenses;
create policy "expenses edit" on public.expenses for update to authenticated
  using (public.is_plus() or public.buy_manager() or (user_id = auth.uid() and public.exp_month_open(spent_on)))
  with check (public.is_plus() or public.buy_manager() or (user_id = auth.uid() and status = 'new' and comp is null and public.exp_month_open(spent_on)));
drop policy if exists "expenses remove" on public.expenses;
create policy "expenses remove" on public.expenses for delete to authenticated
  using (public.is_plus() or (user_id = auth.uid() and public.exp_month_open(spent_on)));

-- approving / rejecting and the compensation: only an Admin+ member
-- (a member correcting an own expense sends it back to „waits“ – that is allowed)
create or replace function public.expenses_review_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if public.is_plus() then return new; end if;
  if new.status is distinct from old.status or new.comp is distinct from old.comp or new.comp_unit is distinct from old.comp_unit
     or new.review_note is distinct from old.review_note then
    if new.user_id = auth.uid() and new.status = 'new' and new.comp is null then return new; end if;
    raise exception 'Patvirtinti išlaidas ir priskirti kompensaciją gali tik Admin+ narys.';
  end if;
  return new;
end $$;
drop trigger if exists expenses_review_guard on public.expenses;
create trigger expenses_review_guard before update on public.expenses for each row execute function public.expenses_review_guard();

notify pgrst, 'reload schema';

-- ============================================================
-- „Išlaidos“: termino nebėra
--  * exp_month_open(d) visada leidžia: narys savo išlaidas ir UTA pylimų pagrindimus (asmeninis / darbo)
--    gali pateikti, taisyti ir trinti bet kada (anksčiau – tik iki kito mėnesio 10 d.)
--  * tvirtinti ir kompensaciją priskirti vis tiek gali tik Admin+ (expenses_rules.sql)
-- Reikia: expenses_rules.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create or replace function public.exp_month_open(d date) returns boolean
  language sql stable as $$
  select d is not null
$$;
grant execute on function public.exp_month_open(date) to authenticated;
notify pgrst, 'reload schema';

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

-- ============================================================
-- Lygių apribojimai (Runner, Freelance, Tech)
--  * Runner ir Freelance: nėra „Prašymų“ (laisvos dienos, atostogos) ir „Pirkinių“ (pasiūlymų)
--  * Freelance: nėra „Inventorizacijos“; „Renginiuose“ (ir kalendoriuje) – tik tie renginiai,
--    kuriuose pats įrašytas (komandos lentelėse ar vadovu), atpažįstama pagal vardą ir pavardę arba slapyvardį
--  * Tech: „Sąskaitose“ – tik savo įkeltos sąskaitos (įkelti gali); „Renginius“ tik mato (nekuria, neredaguoja, netrina)
-- Reikia: user_roles.sql, events_rentals.sql, leave.sql, purchases.sql, stocktake.sql, invoices.sql, calendar_all.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.low_level() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('runner','freelance'), false)
$$;
grant execute on function public.low_level() to authenticated;

-- Prašymai: Runner ir Freelance naujų nepateikia
drop policy if exists "ask leave" on public.leave_requests;
create policy "ask leave" on public.leave_requests for insert to authenticated
  with check (user_id = auth.uid() and public.is_approved() and not public.low_level());

-- Pirkiniai (pasiūlymai): Runner ir Freelance nemato ir nesiūlo
drop policy if exists "proposals view" on public.purchase_proposals;
create policy "proposals view" on public.purchase_proposals for select to authenticated
  using (public.is_approved() and not public.low_level());
drop policy if exists "proposals add" on public.purchase_proposals;
create policy "proposals add" on public.purchase_proposals for insert to authenticated
  with check (public.is_approved() and not public.low_level() and created_by = auth.uid() and status = 'new');

-- Inventorizacija: Runner ir Freelance nemato
drop policy if exists "view stk_items" on public.stk_items;
create policy "view stk_items" on public.stk_items for select to authenticated using (public.can_view('inventory') and not public.low_level());
drop policy if exists "view stk_sessions" on public.stk_sessions;
create policy "view stk_sessions" on public.stk_sessions for select to authenticated using (public.can_view('inventory') and not public.low_level());
drop policy if exists "view stk_log" on public.stk_log;
create policy "view stk_log" on public.stk_log for select to authenticated using (public.can_view('inventory') and not public.low_level());

-- Renginiai: ar aš įrašytas (komandos lentelėse ar vadovu)
create or replace function public.norm_name(t text) returns text
  language sql immutable as $$
  select trim(regexp_replace(regexp_replace(translate(lower(coalesce(t, '')), 'ąčęėįšųūž', 'aceeisuuz'), '[^a-z0-9 ]', ' ', 'g'), '\s+', ' ', 'g'))
$$;
create or replace function public.event_has_me(d jsonb) returns boolean
  language sql stable security definer set search_path = public as $$
  with me as (
    select nullif(public.norm_name(coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.full_name)), '') as n1,
           nullif(public.norm_name(p.nickname), '') as n2
      from public.profiles p where p.id = auth.uid()
  ), who as (
    select en->>'person' as n
      from jsonb_array_elements(case when jsonb_typeof(d->'crew') = 'array' then d->'crew' else '[]'::jsonb end) g,
           jsonb_array_elements(case when jsonb_typeof(g->'entries') = 'array' then g->'entries' else '[]'::jsonb end) en
    union all select d->>'manager'
  )
  select exists (select 1 from me, who where public.norm_name(who.n) <> '' and public.norm_name(who.n) in (me.n1, me.n2))
$$;
grant execute on function public.event_has_me(jsonb) to authenticated;

-- Freelance mato tik savo renginius
drop policy if exists "view events" on public.events;
create policy "view events" on public.events for select to authenticated
  using ((public.can_view('events') or public.can_view('rentals'))
         and (public.my_role() is distinct from 'freelance' or public.event_has_me(data)));

-- kalendorius: Freelance – irgi tik savo renginiai
create or replace function public.calendar_events(d_from date, d_to date)
  returns table (id text, kind text, name text, date_from date, date_to date, venue text, my_roles text[])
  language sql stable security definer set search_path = public as $$
  with me as (
    select public.norm_name(concat_ws(' ', p.first_name, p.last_name)) as n1,
           nullif(public.norm_name(p.nickname), '') as n2
      from public.profiles p where p.id = auth.uid()
  ), ev as (
    select e.id, e.data,
           (e.data->>'date')::date as d1,
           case when coalesce(e.data->>'dateEnd', '') ~ '^\d{4}-\d{2}-\d{2}$' and (e.data->>'dateEnd')::date >= (e.data->>'date')::date
                then (e.data->>'dateEnd')::date else (e.data->>'date')::date end as d2
      from public.events e
     where coalesce(e.data->>'date', '') ~ '^\d{4}-\d{2}-\d{2}$'
       and coalesce(e.data->>'deletedAt', '') = ''
       and coalesce(e.data->>'handoverId', '') = ''
  )
  select ev.id,
         case when ev.data->>'kind' = 'work' then 'work' else 'event' end,
         case when ev.data->>'kind' = 'work' then coalesce(nullif(ev.data->>'title', ''), 'Sandėlio darbai')
              else coalesce(nullif(ev.data->>'name', ''), 'Renginys') end,
         ev.d1, ev.d2,
         nullif(coalesce(nullif(ev.data->>'venue', ''), case when jsonb_typeof(ev.data->'location') = 'string' then ev.data->>'location' end), ''),
         array(
           select concat_ws(' · ', nullif(g->>'title', ''), nullif(en->>'pos', ''))
             from jsonb_array_elements(case when jsonb_typeof(ev.data->'crew') = 'array' then ev.data->'crew' else '[]'::jsonb end) g,
                  jsonb_array_elements(case when jsonb_typeof(g->'entries') = 'array' then g->'entries' else '[]'::jsonb end) en, me
            where public.norm_name(en->>'person') <> '' and public.norm_name(en->>'person') in (me.n1, me.n2)
           union all
           select 'Vadovas' from me
            where public.norm_name(ev.data->>'manager') <> '' and public.norm_name(ev.data->>'manager') in (me.n1, me.n2)
         )
    from ev
   where public.is_approved()
     and (public.my_role() is distinct from 'freelance' or public.event_has_me(ev.data))
     and ev.d1 <= d_to and ev.d2 >= d_from
     and d_to - d_from <= 120
   order by ev.d1, 3
$$;
revoke all on function public.calendar_events(date, date) from public, anon;
grant execute on function public.calendar_events(date, date) to authenticated;

-- Tech: Renginius tik mato
update public.role_permissions set can_view = true, can_edit = false where role = 'tech' and section = 'events';

-- Sąskaitos: be Admin+ (ir ofiso tikrintojų – „invoices check read“) kiekvienas mato tik savo įkeltas
-- (ne gautas per portalą ar el. paštu)
drop policy if exists "invoices read" on public.invoices;
create policy "invoices read" on public.invoices
  for select to authenticated using (public.is_plus() or (created_by = auth.uid() and coalesce(source, '') not in ('portal','email')));

notify pgrst, 'reload schema';

-- ============================================================
-- Chato pranešimai siunčia serveris (ne siuntėjo programėlė)
--  * kiekviena nauja chato žinutė (programoje, per QR, automatinė) duomenų bazėje iškart
--    kviečia „push-notify“ – pranešimas į telefoną ir kompiuterį išeina net jei siuntėjas
--    tuoj pat uždarė programėlę ar dingo ryšys
--  * message_push – kurios žinutės jau praneštos: programėlė vis dar klausia ir pati,
--    bet pranešimas išeina tik vieną kartą (kas pirmesnis)
--  * susitikimų svečių žinutės (guest_id) kaip ir anksčiau – per funkciją „guest“
-- Reikia: pg_net ir suplanuotų užduočių (cron) su x-cron-secret (mail_viskas.sql ar kt.).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create extension if not exists pg_net;

create table if not exists public.message_push (
  message_id uuid primary key,
  at         timestamptz not null default now()
);
alter table public.message_push enable row level security;
revoke all on public.message_push from anon, authenticated;

create or replace function public.messages_push_notify() returns trigger
  language plpgsql security definer set search_path = public, extensions as $$
declare secret text;
begin
  if new.deleted_at is not null or coalesce(to_jsonb(new) ->> 'guest_id', '') <> '' then return new; end if;
  -- the cron secret the scheduled jobs already use
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
    from cron.job where command like '%x-cron-secret%' order by jobid limit 1;
  if secret is null then return new; end if;
  perform net.http_post(
    url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/push-notify',
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', secret),
    body    := jsonb_build_object('mode', 'message-db', 'message_id', new.id),
    timeout_milliseconds := 20000
  );
  return new;
exception when others then
  return new;   -- a notification that fails never blocks the message
end $$;
revoke all on function public.messages_push_notify() from public, anon, authenticated;

drop trigger if exists messages_push_notify on public.messages;
create trigger messages_push_notify after insert on public.messages
  for each row execute function public.messages_push_notify();

notify pgrst, 'reload schema';

-- ============================================================
-- „Darbų planas“
--  * work_plans – planas (pvz. „Automobilių priežiūra“): grupės (pvz. „Dokumentai ir privaloma įranga“)
--    su teiginiais (pvz. „Tech. pasas“, „Draudimo polisas“), kaip dažnai (kas dieną, darbo dienomis,
--    kas savaitę, kas mėnesį, kas N dienų, kartą), iki kada, kam priskirta
--    Kuria ir keičia tik Admin nariai; narys mato tik jam priskirtus planus
--  * work_plan_runs – nario užpildymas vienam laikotarpiui: kiekvienas teiginys Taip / Ne, komentaras,
--    nuotraukos. Kiekvieno pažymėjimo, komentaro ir nuotraukos laiką įrašo SERVERIS (ne telefonas)
--  * pateiktas (atliktas) užpildymas lieka archyve; Admin mato visus, narys – savo
--  * nuotraukos: saugykla 'work-files', kelias <nario id>/<užpildymo id>/<failas>
-- Reikia: user_roles.sql (is_admin, is_approved). Neatliktų darbų pranešimus siunčia „push-notify“ (cron).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.work_plans (
  id          uuid primary key default gen_random_uuid(),
  title       text not null,
  description text not null default '',
  groups      jsonb not null default '[]'::jsonb,      -- [{id, title, items:[{id, text, photo:'no'|'optional'|'required'}]}]
  freq        text not null default 'weekly' check (freq in ('daily','workdays','weekly','monthly','every_n','once')),
  weekday     smallint check (weekday is null or weekday between 1 and 7),   -- 1 = pirmadienis
  month_day   smallint check (month_day is null or month_day between 1 and 31),
  every_days  smallint check (every_days is null or every_days between 1 and 366),
  start_date  date not null default ((now() at time zone 'Europe/Vilnius')::date),
  due_time    text not null default '23:59' check (due_time ~ '^\d{2}:\d{2}$'),
  assignees   uuid[] not null default '{}',
  active      boolean not null default true,
  created_by  uuid default auth.uid(),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists work_plans_assignees on public.work_plans using gin (assignees);

create table if not exists public.work_plan_runs (
  id          uuid primary key default gen_random_uuid(),
  plan_id     uuid not null references public.work_plans(id) on delete cascade,
  user_id     uuid not null references auth.users(id) on delete cascade,
  period      date not null,                            -- the day the work belongs to (e.g. that Monday)
  due_at      timestamptz,
  answers     jsonb not null default '{}'::jsonb,       -- {itemId: {v:'yes'|'no', at, comment, comment_at, photos:[{path,name,at}]}}
  snapshot    jsonb,                                    -- the plan's title and groups as they were when filled in
  status      text not null default 'open' check (status in ('open','done')),
  started_at  timestamptz not null default now(),
  done_at     timestamptz,
  updated_at  timestamptz not null default now(),
  unique (plan_id, user_id, period)
);
create index if not exists work_plan_runs_user on public.work_plan_runs (user_id, period desc);
create index if not exists work_plan_runs_plan on public.work_plan_runs (plan_id, period desc);

-- who keeps the plans: Admin (any Admin level)
create or replace function public.wp_admin() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'admin' from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.wp_admin() to authenticated;

alter table public.work_plans enable row level security;
drop policy if exists "wp view" on public.work_plans;
create policy "wp view" on public.work_plans for select to authenticated
  using (public.wp_admin() or (public.is_approved() and auth.uid() = any(assignees)));
drop policy if exists "wp edit" on public.work_plans;
create policy "wp edit" on public.work_plans for all to authenticated
  using (public.wp_admin()) with check (public.wp_admin());
revoke all on public.work_plans from anon;
grant select, insert, update, delete on public.work_plans to authenticated;

alter table public.work_plan_runs enable row level security;
drop policy if exists "wpr view" on public.work_plan_runs;
create policy "wpr view" on public.work_plan_runs for select to authenticated
  using (user_id = auth.uid() or public.wp_admin());
drop policy if exists "wpr add" on public.work_plan_runs;
create policy "wpr add" on public.work_plan_runs for insert to authenticated
  with check (user_id = auth.uid() and status = 'open'
              and exists (select 1 from public.work_plans p where p.id = plan_id and p.active and auth.uid() = any(p.assignees)));
drop policy if exists "wpr fill" on public.work_plan_runs;
create policy "wpr fill" on public.work_plan_runs for update to authenticated
  using ((user_id = auth.uid() and status = 'open') or public.wp_admin())
  with check (user_id = auth.uid() or public.wp_admin());
drop policy if exists "wpr remove" on public.work_plan_runs;
create policy "wpr remove" on public.work_plan_runs for delete to authenticated
  using (public.wp_admin());
revoke all on public.work_plan_runs from anon;
grant select, insert, update, delete on public.work_plan_runs to authenticated;

-- the server's clock: when each answer, comment and photo was given, when it was handed in
create or replace function public.work_plan_runs_stamp() returns trigger
  language plpgsql set search_path = public as $$
declare k text; n jsonb; o jsonb; a jsonb := '{}'::jsonb; ts text := to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if tg_op = 'INSERT' then
    new.started_at := now(); new.done_at := null;
    if new.status = 'done' then new.status := 'open'; end if;
  end if;
  for k, n in select * from jsonb_each(coalesce(new.answers, '{}'::jsonb)) loop
    o := case when tg_op = 'UPDATE' then coalesce(old.answers -> k, '{}'::jsonb) else '{}'::jsonb end;
    if jsonb_typeof(n) <> 'object' then continue; end if;
    if (n ->> 'v') is distinct from (o ->> 'v') then n := n || jsonb_build_object('at', ts); else n := n || jsonb_build_object('at', o -> 'at'); end if;
    if coalesce(n ->> 'comment', '') is distinct from coalesce(o ->> 'comment', '') then n := n || jsonb_build_object('comment_at', ts); else n := n || jsonb_build_object('comment_at', o -> 'comment_at'); end if;
    -- a photo keeps the time it was first added
    n := n || jsonb_build_object('photos', coalesce((
      select jsonb_agg(case when exists (select 1 from jsonb_array_elements(coalesce(o -> 'photos', '[]'::jsonb)) op where op ->> 'path' = p ->> 'path')
                            then p || jsonb_build_object('at', (select op -> 'at' from jsonb_array_elements(o -> 'photos') op where op ->> 'path' = p ->> 'path' limit 1))
                            else p || jsonb_build_object('at', ts) end)
        from jsonb_array_elements(case when jsonb_typeof(n -> 'photos') = 'array' then n -> 'photos' else '[]'::jsonb end) p), '[]'::jsonb));
    a := a || jsonb_build_object(k, jsonb_strip_nulls(n));
  end loop;
  new.answers := a;
  if tg_op = 'UPDATE' then
    new.plan_id := old.plan_id; new.user_id := old.user_id; new.period := old.period; new.started_at := old.started_at;
    if new.status = 'done' and old.status <> 'done' then new.done_at := now();
    elsif new.status = 'open' then new.done_at := null;
    else new.done_at := old.done_at; end if;
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists work_plan_runs_stamp on public.work_plan_runs;
create trigger work_plan_runs_stamp before insert or update on public.work_plan_runs
  for each row execute function public.work_plan_runs_stamp();

create or replace function public.work_plans_touch() returns trigger
  language plpgsql set search_path = public as $$
begin
  new.updated_at := now();
  if tg_op = 'INSERT' then new.created_by := auth.uid(); new.created_at := now();
  else new.created_by := old.created_by; new.created_at := old.created_at; end if;
  return new;
end $$;
drop trigger if exists work_plans_touch on public.work_plans;
create trigger work_plans_touch before insert or update on public.work_plans
  for each row execute function public.work_plans_touch();

-- changes at once (Realtime)
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'work_plans') then
      execute 'alter publication supabase_realtime add table public.work_plans'; end if;
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'work_plan_runs') then
      execute 'alter publication supabase_realtime add table public.work_plan_runs'; end if;
  end if;
end $$;

-- photos
insert into storage.buckets (id, name, public) values ('work-files', 'work-files', false) on conflict (id) do nothing;
drop policy if exists "work files view" on storage.objects;
create policy "work files view" on storage.objects for select to authenticated
  using (bucket_id = 'work-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.wp_admin()));
drop policy if exists "work files add" on storage.objects;
create policy "work files add" on storage.objects for insert to authenticated
  with check (bucket_id = 'work-files' and (storage.foldername(name))[1] = auth.uid()::text and public.is_approved());
drop policy if exists "work files remove" on storage.objects;
create policy "work files remove" on storage.objects for delete to authenticated
  using (bucket_id = 'work-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.wp_admin()));

notify pgrst, 'reload schema';

-- ============================================================
-- RFID (Chainway C72 ir kiti skaitytuvai „klaviatūros“ režimu): puslapis rfid.html
--  * rfid_tags – kuri RFID žyma (EPC) kuriam sandėlio daiktui priklauso (ir, jei reikia, vieneto nr.)
--    mato visi patvirtinti nariai; priskiria / keičia / trina tie, kas redaguoja „Įrangą“
--  * rfid_inventories – inventorizacijos skenavimas: kokios žymos rastos ir kada
--    pradeda tie, kas mato „Įrangą“; mato tie, kas mato „Įrangą“
-- Reikia: user_roles.sql (is_approved, can_view, can_edit).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.rfid_tags (
  epc             text primary key check (length(epc) between 4 and 128),
  item_id         text not null,
  item_name       text,
  unit            text not null default '',
  note            text not null default '',
  created_by      uuid default auth.uid(),
  created_by_name text,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);
create index if not exists rfid_tags_item on public.rfid_tags (item_id);

create table if not exists public.rfid_inventories (
  id              uuid primary key default gen_random_uuid(),
  title           text not null default '',
  tags            jsonb not null default '[]'::jsonb,       -- [{epc, at}]
  created_by      uuid default auth.uid(),
  created_by_name text,
  created_at      timestamptz not null default now(),
  finished_at     timestamptz
);
create index if not exists rfid_inventories_time on public.rfid_inventories (created_at desc);

-- who wrote it: set by the server
create or replace function public.rfid_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  new.epc := upper(regexp_replace(coalesce(new.epc, ''), '\s+', '', 'g'));
  if tg_op = 'INSERT' then
    new.created_by := auth.uid(); new.created_at := now();
    new.created_by_name := coalesce((select nullif(trim(concat_ws(' ', p.first_name, p.last_name)), '') from public.profiles p where p.id = auth.uid()), new.created_by_name);
  else
    new.created_by := old.created_by; new.created_at := old.created_at; new.created_by_name := old.created_by_name;
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists rfid_tags_stamp on public.rfid_tags;
create trigger rfid_tags_stamp before insert or update on public.rfid_tags for each row execute function public.rfid_stamp();

create or replace function public.rfid_inv_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.created_by := auth.uid(); new.created_at := now();
    new.created_by_name := coalesce((select nullif(trim(concat_ws(' ', p.first_name, p.last_name)), '') from public.profiles p where p.id = auth.uid()), new.created_by_name);
  else
    new.created_by := old.created_by; new.created_at := old.created_at; new.created_by_name := old.created_by_name;
  end if;
  return new;
end $$;
drop trigger if exists rfid_inventories_stamp on public.rfid_inventories;
create trigger rfid_inventories_stamp before insert or update on public.rfid_inventories for each row execute function public.rfid_inv_stamp();

alter table public.rfid_tags enable row level security;
drop policy if exists "rfid tags view" on public.rfid_tags;
create policy "rfid tags view" on public.rfid_tags for select to authenticated using (public.is_approved());
drop policy if exists "rfid tags edit" on public.rfid_tags;
create policy "rfid tags edit" on public.rfid_tags for all to authenticated
  using (public.can_edit('inventory')) with check (public.can_edit('inventory'));
revoke all on public.rfid_tags from anon;
grant select, insert, update, delete on public.rfid_tags to authenticated;

alter table public.rfid_inventories enable row level security;
drop policy if exists "rfid inv view" on public.rfid_inventories;
create policy "rfid inv view" on public.rfid_inventories for select to authenticated using (public.can_view('inventory'));
drop policy if exists "rfid inv add" on public.rfid_inventories;
create policy "rfid inv add" on public.rfid_inventories for insert to authenticated with check (public.can_view('inventory'));
drop policy if exists "rfid inv change" on public.rfid_inventories;
create policy "rfid inv change" on public.rfid_inventories for update to authenticated
  using (created_by = auth.uid() or public.can_edit('inventory')) with check (created_by = auth.uid() or public.can_edit('inventory'));
drop policy if exists "rfid inv remove" on public.rfid_inventories;
create policy "rfid inv remove" on public.rfid_inventories for delete to authenticated using (public.can_edit('inventory'));
revoke all on public.rfid_inventories from anon;
grant select, insert, update, delete on public.rfid_inventories to authenticated;

notify pgrst, 'reload schema';

-- ============================================================
-- RFID: unikalus kodas kiekvienam pažymėtam vienetui (pvz. ES-00042)
--  * kiekviena priskirta žyma (rfid_tags) gauna savo kodą – jį duoda SERVERIS, kartojasi niekada
--  * kodas lieka tas pats, net jei žyma perkeliama kitam daiktui ar keičiamas vieneto nr.
--  * jau priskirtos žymos gauna kodus iš eilės pagal priskyrimo laiką
--  * kodas matomas „Įrangoje“ (prie daikto – RFID vienetai) ir RFID skeneryje
-- Reikia: rfid.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create sequence if not exists public.rfid_code_seq;
alter table public.rfid_tags add column if not exists code text;

-- the ones without a code: one by one, the oldest first
do $$ declare r record; begin
  for r in select epc from public.rfid_tags where code is null order by created_at, epc loop
    update public.rfid_tags set code = 'ES-' || lpad(nextval('public.rfid_code_seq')::text, 5, '0') where epc = r.epc;
  end loop;
end $$;
create unique index if not exists rfid_tags_code on public.rfid_tags (code);

create or replace function public.rfid_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  new.epc := upper(regexp_replace(coalesce(new.epc, ''), '\s+', '', 'g'));
  if tg_op = 'INSERT' then
    new.created_by := auth.uid(); new.created_at := now();
    new.created_by_name := coalesce((select nullif(trim(concat_ws(' ', p.first_name, p.last_name)), '') from public.profiles p where p.id = auth.uid()), new.created_by_name);
    new.code := 'ES-' || lpad(nextval('public.rfid_code_seq')::text, 5, '0');
  else
    new.created_by := old.created_by; new.created_at := old.created_at; new.created_by_name := old.created_by_name;
    new.code := coalesce(old.code, 'ES-' || lpad(nextval('public.rfid_code_seq')::text, 5, '0'));
  end if;
  new.updated_at := now();
  return new;
end $$;

notify pgrst, 'reload schema';

-- ============================================================
-- Team Tracker be PIN kodo ir be registracijos
--  * kiekvienas patvirtintas programėlės narys naudojasi Team Tracker savo paskyra – PIN nebereikia
--  * atidarius Team Tracker narys sukuriamas automatiškai (vardas ir pavardė – iš profilio);
--    jau užregistruotas narys su tuo pačiu vardu ir pavarde susiejamas su paskyra
--  * savo laiką narys valdo tik savo paskyra; kitų laiką, kaip ir anksčiau, mato Admin, Office, Projektų vadovai
--  * demo darbuotojo laiką gali peržiūrėti visi
-- Reikia: tracker.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- the member tied to the signed-in account is always allowed; a key (token) from older devices still works
create or replace function public.tt_auth(m uuid, p_pin text, p_token text, admin_ok boolean) returns text
  language plpgsql security definer set search_path = public, extensions as $$
declare r public.tracker_members;
begin
  if auth.uid() is null or not public.is_approved() then return 'Reikia prisijungti prie programėlės.'; end if;
  select * into r from public.tracker_members where id = m;
  if r.id is null then return 'Tokio nario nėra.'; end if;
  if r.user_id = auth.uid() then return null; end if;
  if p_token is not null and exists (select 1 from public.tracker_tokens where member_id = m and token_hash = encode(digest(p_token, 'sha256'), 'hex')) then return null; end if;
  -- looking at the time: Admin / Office / Projektų vadovas – anyone's; everyone – the demo
  if admin_ok and (public.tt_manager() or r.demo) then return null; end if;
  return 'Savo laiką gali tvarkyti tik pats narys.';
end $$;
revoke all on function public.tt_auth(uuid, text, text, boolean) from public, anon, authenticated;

-- my member: found or made on first use
create or replace function public.tt_me() returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare mid uuid; nm text; base text; n int := 1; e text;
begin
  if auth.uid() is null or not public.is_approved() then return jsonb_build_object('error', 'Reikia prisijungti prie programėlės.'); end if;
  select id into mid from public.tracker_members where user_id = auth.uid();
  if mid is null then
    select nullif(btrim(coalesce(first_name,'') || ' ' || coalesce(last_name,'')), ''), email into base, e from public.profiles where id = auth.uid();
    base := coalesce(base, nullif(split_part(coalesce(e, ''), '@', 1), ''), 'Narys');
    -- a member registered earlier with the same name and not tied to anyone: it is mine
    select min(id::text)::uuid into mid from public.tracker_members
      where user_id is null and not demo and lower(btrim(name)) = lower(base)
      having count(*) = 1;
    if mid is not null then
      update public.tracker_members set user_id = auth.uid() where id = mid and user_id is null;
    else
      nm := base;
      while exists (select 1 from public.tracker_members where lower(name) = lower(nm)) loop
        n := n + 1; nm := base || ' (' || n || ')';
      end loop;
      insert into public.tracker_members (name, pin_hash, user_id)
        values (nm, crypt(encode(gen_random_bytes(12), 'hex'), gen_salt('bf')), auth.uid()) returning id into mid;
    end if;
  end if;
  return jsonb_build_object('id', mid, 'state', public.tt_state_of(mid));
end $$;
revoke all on function public.tt_me() from public, anon;
grant execute on function public.tt_me() to authenticated;

notify pgrst, 'reload schema';

-- ============================================================
-- Sąskaitos → „Transporto nuoma“
--  * nauja sąskaitų rūšis 'vehrent' – automobilių, mikroautobusų, fūrų nuomos sąskaitos
--  * plates – sąskaitoje rasti valstybiniai numeriai (įkeliant nuskaitomi iš PDF, galima pataisyti)
--  * vehrent_invoices(nuo, iki) – Ataskaitos → Transporto nuoma: visos tokios sąskaitos (nesvarbu, patvirtintos ar ne);
--    mato tie, kas mato Renginius ar Transportą, ir Admin+
-- Reikia: invoices.sql, invoice_check.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.invoices drop constraint if exists invoices_kind_check;
alter table public.invoices add constraint invoices_kind_check check (kind in ('freelance','service','rent','purchase','other','vehrent'));
alter table public.invoices add column if not exists plates text[] not null default '{}';

-- the office may set this kind too (invoice_office keeps its own list of kinds)
do $$ declare f record; d text; begin
  for f in select p.oid from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.proname = 'invoice_office' loop
    d := pg_get_functiondef(f.oid);
    if position('''vehrent''' in d) = 0 and position($q$('freelance','service','rent','purchase','other')$q$ in d) > 0 then
      execute replace(d, $q$('freelance','service','rent','purchase','other')$q$, $q$('freelance','service','rent','purchase','other','vehrent')$q$);
    end if;
  end loop;
end $$;

create or replace function public.vehrent_invoices(p_from date, p_to date) returns setof jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', i.id, 'supplier', i.supplier, 'number', i.number, 'amount', i.amount, 'invoice_date', i.invoice_date,
                            'created_at', i.created_at, 'status', i.status, 'plates', i.plates, 'note', i.note)
    from public.invoices i
   where i.kind = 'vehrent'
     and coalesce(i.invoice_date, (i.created_at at time zone 'Europe/Vilnius')::date) between p_from and p_to
     and (public.is_plus() or public.can_view('events') or public.can_view('fleet'))
   order by coalesce(i.invoice_date, (i.created_at at time zone 'Europe/Vilnius')::date)
$$;
revoke all on function public.vehrent_invoices(date, date) from public, anon;
grant execute on function public.vehrent_invoices(date, date) to authenticated;

notify pgrst, 'reload schema';

-- ============================================================
-- Sąskaitos → „Transporto nuoma“: detalizacija
--  * veh_lines – sąskaitos eilutės: kuris transportas (valst. nr.), kas nuomota, nuo kada iki kada, suma
--    [{plate, desc, from, to, qty, total, kind:'rent'|'extra'}]; nuskaitoma iš PDF arba įrašoma ranka
--  * Ataskaitos → Transporto nuoma skaičiuoja kiekvieną automobilį pagal jo eilutę (ne dalijant sumą po lygiai)
-- Reikia: invoices_vehrent.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.invoices add column if not exists veh_lines jsonb;

create or replace function public.vehrent_invoices(p_from date, p_to date) returns setof jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', i.id, 'supplier', i.supplier, 'number', i.number, 'amount', i.amount, 'invoice_date', i.invoice_date,
                            'created_at', i.created_at, 'status', i.status, 'plates', i.plates, 'note', i.note, 'veh_lines', i.veh_lines)
    from public.invoices i
   where i.kind = 'vehrent'
     and coalesce(i.invoice_date, (i.created_at at time zone 'Europe/Vilnius')::date) between p_from and p_to
     and (public.is_plus() or public.can_view('events') or public.can_view('fleet'))
   order by coalesce(i.invoice_date, (i.created_at at time zone 'Europe/Vilnius')::date)
$$;
revoke all on function public.vehrent_invoices(date, date) from public, anon;
grant execute on function public.vehrent_invoices(date, date) to authenticated;

-- the detail written / corrected later (an invoice uploaded before the detail existed): the uploader, Office, Admin+
create or replace function public.invoice_vehlines(p_id uuid, p_lines jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare v public.invoices; pl text[];
begin
  select * into v from public.invoices where id = p_id for update;
  if v.id is null then raise exception 'Sąskaitos nėra.'; end if;
  if v.kind <> 'vehrent' then raise exception 'Tai ne transporto nuomos sąskaita.'; end if;
  if not (v.created_by = auth.uid() or public.is_plus() or coalesce(public.my_role() in ('admin','office','pm'), false)) then raise exception 'Nėra teisės.'; end if;
  if jsonb_typeof(coalesce(p_lines, '[]'::jsonb)) <> 'array' or jsonb_array_length(coalesce(p_lines, '[]'::jsonb)) > 200 then raise exception 'Netinkama detalizacija.'; end if;
  select coalesce(array_agg(distinct upper(btrim(x ->> 'plate'))) filter (where coalesce(btrim(x ->> 'plate'), '') <> ''), '{}') into pl
    from jsonb_array_elements(coalesce(p_lines, '[]'::jsonb)) x;
  update public.invoices set veh_lines = p_lines, plates = pl where id = p_id returning * into v;
  return to_jsonb(v);
end $$;
revoke all on function public.invoice_vehlines(uuid, jsonb) from public, anon;
grant execute on function public.invoice_vehlines(uuid, jsonb) to authenticated;

notify pgrst, 'reload schema';

-- ============================================================
-- „Prisijungimai / Kontaktai“
--  * keturios grafos: Programų prisijungimai (app), Puslapių prisijungimai (web), Kontaktai (contact), El. paštai (email)
--  * mato ir tvarko Office, Projektų vadovai ir Admin; El. paštus – tik Admin
--  * slaptažodžiai saugomi UŽŠIFRUOTI (pgcrypto); sąraše jų nėra – atskleidžiami tik paspaudus akutę,
--    kiekvienas atskleidimas įrašomas (cred_access: kas ir kada)
--  * lentelės tiesiogiai nepasiekiamos – tik per funkcijas cred_list / cred_secret / cred_save / cred_delete
-- Reikia: user_roles.sql (my_role). Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create extension if not exists pgcrypto with schema extensions;
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

-- the encryption key: made once, here in the database, never sent anywhere
create table if not exists private.cred_key (id int primary key default 1 check (id = 1), k text not null);
insert into private.cred_key (id, k) values (1, encode(extensions.gen_random_bytes(32), 'hex')) on conflict (id) do nothing;
revoke all on private.cred_key from public, anon, authenticated;

create table if not exists public.cred_entries (
  id           uuid primary key default gen_random_uuid(),
  cat          text not null check (cat in ('app','web','contact','email')),
  title        text not null default '',     -- programa / puslapis / vardas / el. pašto adresas
  url          text not null default '',
  login        text not null default '',     -- prisijungimo vardas
  secret_enc   bytea,                        -- slaptažodis (užšifruotas)
  company      text not null default '',
  phone        text not null default '',
  email        text not null default '',
  note         text not null default '',
  created_by   uuid default auth.uid(),
  created_at   timestamptz not null default now(),
  updated_by   uuid,
  updated_name text,
  updated_at   timestamptz not null default now()
);
create index if not exists cred_entries_cat on public.cred_entries (cat, lower(title));
alter table public.cred_entries enable row level security;
revoke all on public.cred_entries from anon, authenticated;

create table if not exists public.cred_access (
  id        bigserial primary key,
  entry_id  uuid references public.cred_entries(id) on delete cascade,
  user_id   uuid,
  user_name text,
  at        timestamptz not null default now()
);
alter table public.cred_access enable row level security;
revoke all on public.cred_access from anon, authenticated;

-- who may: Office and up; El. paštai – Admin only
create or replace function public.cred_can(p_cat text) returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','pm','office'), false) and (p_cat <> 'email' or coalesce(public.my_role() = 'admin', false))
$$;
grant execute on function public.cred_can(text) to authenticated;

create or replace function public.cred_list(p_cat text) returns setof jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', e.id, 'cat', e.cat, 'title', e.title, 'url', e.url, 'login', e.login, 'has_secret', e.secret_enc is not null,
           'company', e.company, 'phone', e.phone, 'email', e.email, 'note', e.note, 'updated_name', e.updated_name, 'updated_at', e.updated_at,
           'views', (select count(*) from public.cred_access a where a.entry_id = e.id),
           'last_view', (select jsonb_build_object('who', a.user_name, 'at', a.at) from public.cred_access a where a.entry_id = e.id order by a.at desc limit 1))
    from public.cred_entries e
   where e.cat = p_cat and public.cred_can(p_cat)
   order by lower(e.title)
$$;

create or replace function public.cred_secret(p_id uuid) returns text
  language plpgsql security definer set search_path = public, extensions as $$
declare e public.cred_entries; k text;
begin
  select * into e from public.cred_entries where id = p_id;
  if e.id is null or not public.cred_can(e.cat) then raise exception 'Nėra teisės.'; end if;
  if e.secret_enc is null then return ''; end if;
  select ck.k into k from private.cred_key ck where ck.id = 1;
  insert into public.cred_access (entry_id, user_id, user_name) values (e.id, auth.uid(), (select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid()));
  return extensions.pgp_sym_decrypt(e.secret_enc, k);
end $$;

-- p_secret: null – the password stays as it is, '' – removed, other – the new one
create or replace function public.cred_save(p_id uuid, p_cat text, p_data jsonb, p_secret text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare e public.cred_entries; k text; f text; d jsonb := coalesce(p_data, '{}'::jsonb);
begin
  if not public.cred_can(p_cat) then raise exception 'Nėra teisės.'; end if;
  foreach f in array array['title','url','login','company','phone','email','note'] loop
    if length(coalesce(d ->> f, '')) > 2000 then raise exception 'Per ilgas laukas: %', f; end if;
  end loop;
  select ck.k into k from private.cred_key ck where ck.id = 1;
  if p_id is null then
    insert into public.cred_entries (cat, title, url, login, company, phone, email, note, secret_enc, created_by, updated_by, updated_name)
    values (p_cat, coalesce(d->>'title',''), coalesce(d->>'url',''), coalesce(d->>'login',''), coalesce(d->>'company',''), coalesce(d->>'phone',''),
            coalesce(d->>'email',''), coalesce(d->>'note',''),
            case when coalesce(p_secret,'') = '' then null else extensions.pgp_sym_encrypt(p_secret, k) end, auth.uid(), auth.uid(), (select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid()))
    returning * into e;
  else
    select * into e from public.cred_entries where id = p_id for update;
    if e.id is null or not public.cred_can(e.cat) then raise exception 'Nėra teisės.'; end if;
    update public.cred_entries set title = coalesce(d->>'title',''), url = coalesce(d->>'url',''), login = coalesce(d->>'login',''),
      company = coalesce(d->>'company',''), phone = coalesce(d->>'phone',''), email = coalesce(d->>'email',''), note = coalesce(d->>'note',''),
      secret_enc = case when p_secret is null then secret_enc when p_secret = '' then null else extensions.pgp_sym_encrypt(p_secret, k) end,
      updated_by = auth.uid(), updated_name = (select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid()), updated_at = now()
    where id = p_id returning * into e;
  end if;
  return jsonb_build_object('id', e.id);
end $$;

create or replace function public.cred_delete(p_id uuid) returns void
  language plpgsql security definer set search_path = public as $$
declare e public.cred_entries;
begin
  select * into e from public.cred_entries where id = p_id;
  if e.id is null or not public.cred_can(e.cat) then raise exception 'Nėra teisės.'; end if;
  delete from public.cred_entries where id = p_id;
end $$;

revoke all on function public.cred_list(text), public.cred_secret(uuid), public.cred_save(uuid, text, jsonb, text), public.cred_delete(uuid) from public, anon;
grant execute on function public.cred_list(text), public.cred_secret(uuid), public.cred_save(uuid, text, jsonb, text), public.cred_delete(uuid) to authenticated;

notify pgrst, 'reload schema';

-- Vairuotojų kodai (UTA): kiekvienam renginyje priskirtam vairuotojui – unikalus 4 skaitmenų kodas
-- (pagal vardą pavardę; tas pats žmogus visada gauna tą patį kodą, nesvarbu, darbuotojas ar ne).
-- Kodą vairuotojas įrašo pildydamas kuro išlaidą ar žymėdamas kuro pylimą prie transporto.
-- Antras pylimas ta pačia UTA kortele per 1 val. paaiškinamas (uta_tx_notes).

create table if not exists public.driver_codes (
  key text primary key,                       -- vardas pavardė, normalizuota (mažosios, be lietuviškų raidžių)
  name text not null,
  code text not null unique check (code ~ '^[0-9]{4}$'),
  created_at timestamptz not null default now(),
  created_by uuid default auth.uid()
);
alter table public.driver_codes enable row level security;
drop policy if exists "driver codes view" on public.driver_codes;
create policy "driver codes view" on public.driver_codes for select to authenticated
  using (coalesce(public.my_role(), '') not in ('', 'pending', 'blocked'));
grant select on public.driver_codes to authenticated;

-- p: [{ "k": "jonas jonaitis", "n": "Jonas Jonaitis" }, …] → visų jų kodai (trūkstami sukuriami)
create or replace function public.driver_codes_ensure(p jsonb)
returns setof public.driver_codes
language plpgsql security definer set search_path = public as $$
declare x jsonb; k text; c text; n int;
begin
  if coalesce(public.my_role(), '') in ('', 'pending', 'blocked') then raise exception 'not allowed'; end if;
  for x in select * from jsonb_array_elements(coalesce(p, '[]'::jsonb)) loop
    k := lower(trim(x->>'k'));
    if k is null or k = '' or length(k) > 120 then continue; end if;
    if exists (select 1 from public.driver_codes where key = k) then continue; end if;
    n := 0;
    loop
      n := n + 1;
      c := lpad((1000 + floor(random() * 9000))::int::text, 4, '0');
      begin
        insert into public.driver_codes(key, name, code) values (k, left(trim(coalesce(x->>'n', k)), 120), c);
        exit;
      exception when unique_violation then
        if exists (select 1 from public.driver_codes where key = k) then exit; end if;   -- kitas ką tik sukūrė
        if n > 200 then raise exception 'no free code'; end if;
      end;
    end loop;
  end loop;
  return query select d.* from public.driver_codes d
    where d.key in (select lower(trim(e->>'k')) from jsonb_array_elements(coalesce(p, '[]'::jsonb)) e);
end $$;
revoke all on function public.driver_codes_ensure(jsonb) from public, anon;
grant execute on function public.driver_codes_ensure(jsonb) to authenticated;

-- kas pylė: kodas prie kuro išlaidos
alter table public.expenses add column if not exists driver_code text;

-- pylimo paaiškinimas (pvz. antras pylimas ta pačia kortele per 1 val.: kitas transportas, bakelis…)
create table if not exists public.uta_tx_notes (
  tx_id uuid primary key references public.uta_tx(id) on delete cascade,
  kind text not null check (kind in ('card', 'other', 'rent', 'can', 'misc')),
  plate text,
  note text,
  by_id uuid default auth.uid(),
  by_name text,
  updated_at timestamptz not null default now()
);
alter table public.uta_tx_notes enable row level security;
drop policy if exists "uta notes view" on public.uta_tx_notes;
create policy "uta notes view" on public.uta_tx_notes for select to authenticated using (public.can_view('fleet') or public.can_view('stats'));
drop policy if exists "uta notes edit" on public.uta_tx_notes;
create policy "uta notes edit" on public.uta_tx_notes for all to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
grant select, insert, update, delete on public.uta_tx_notes to authenticated;

-- QR puslapis (Kuro pylimas): kodo patikrinimas (p_log null) ir įrašymas prie ką tik užregistruoto pylimo
create or replace function public.vehicle_log_code(p_token text, p_log uuid, p_code text)
returns boolean language plpgsql security definer set search_path = public as $$
declare v jsonb; nm text;
begin
  v := public.vehicle_by_token(p_token);
  if v is null then raise exception 'QR kodas nebegalioja.'; end if;
  if coalesce(p_code, '') !~ '^[0-9]{4}$' then return false; end if;
  select name into nm from public.driver_codes where code = p_code;
  if nm is null then return false; end if;
  if p_log is not null then
    update public.vehicle_logs set data = coalesce(data, '{}'::jsonb) || jsonb_build_object('driver_code', p_code, 'driver_name', nm)
     where id = p_log and vehicle_id = v ->> 'id' and kind = 'fuel' and data ->> 'via' = 'qr' and created_at > now() - interval '15 minutes';
  end if;
  return true;
end $$;
revoke all on function public.vehicle_log_code(text, uuid, text) from public;
grant execute on function public.vehicle_log_code(text, uuid, text) to anon, authenticated;

notify pgrst, 'reload schema';

-- ============================================================
-- Sandėlis → „Likučiai“: einamieji daiktai (Tape, Skočas, Zateškės, Strečas, Baterijos…)
--  * stock_cats  – kategorijos (pridedamos pačių)
--  * stock_items – daiktai: kategorija, vienetai ('pcs' – vnt., 'pct' – %), kada laikyti „baigiasi“
--  * stock_counts – skaičiai iš darbų planų: darbų plano punktas „Likutis“ (item.stock = daikto id)
--    – pildant planą įrašytas skaičius automatiškai įrašomas čia (trigeris ant work_plan_runs)
-- Reikia: user_roles.sql (is_approved, can_edit), work_plans.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.stock_cats (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  sort       int not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.stock_items (
  id         uuid primary key default gen_random_uuid(),
  cat_id     uuid references public.stock_cats(id) on delete set null,
  name       text not null,
  unit       text not null default 'pcs' check (unit in ('pcs', 'pct')),
  min_level  numeric,                       -- mažiau – „baigiasi“
  note       text,
  sort       int not null default 0,
  active     boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.stock_counts (
  id        uuid primary key default gen_random_uuid(),
  item_id   uuid not null references public.stock_items(id) on delete cascade,
  value     numeric not null,
  run_id    uuid references public.work_plan_runs(id) on delete cascade,
  plan_id   uuid,
  plan_title text,
  user_id   uuid,
  user_name text,
  period    date,
  at        timestamptz not null default now(),
  unique (run_id, item_id)
);
create index if not exists stock_counts_item on public.stock_counts (item_id, at desc);

alter table public.stock_cats enable row level security;
alter table public.stock_items enable row level security;
alter table public.stock_counts enable row level security;
drop policy if exists "stock cats view" on public.stock_cats;
create policy "stock cats view" on public.stock_cats for select to authenticated using (public.is_approved());
drop policy if exists "stock cats edit" on public.stock_cats;
create policy "stock cats edit" on public.stock_cats for all to authenticated using (public.can_edit('inventory')) with check (public.can_edit('inventory'));
drop policy if exists "stock items view" on public.stock_items;
create policy "stock items view" on public.stock_items for select to authenticated using (public.is_approved());
drop policy if exists "stock items edit" on public.stock_items;
create policy "stock items edit" on public.stock_items for all to authenticated using (public.can_edit('inventory')) with check (public.can_edit('inventory'));
drop policy if exists "stock counts view" on public.stock_counts;
create policy "stock counts view" on public.stock_counts for select to authenticated using (public.is_approved());
-- skaičiai įrašomi tik per darbų planą (trigeris)
revoke all on public.stock_cats, public.stock_items, public.stock_counts from anon;
grant select, insert, update, delete on public.stock_cats, public.stock_items to authenticated;
grant select on public.stock_counts to authenticated;

-- darbų plano užpildymas → likučiai: kiekvienas punktas su „stock“, kurio atsakyme yra skaičius (n)
create or replace function public.stock_counts_from_run() returns trigger
  language plpgsql security definer set search_path = public as $$
declare it jsonb; a jsonb; sid uuid; v numeric; nm text;
begin
  select trim(coalesce(first_name, '') || ' ' || coalesce(last_name, '')) into nm from public.profiles where id = new.user_id;
  for it in select i from jsonb_array_elements(case when jsonb_typeof(new.snapshot -> 'groups') = 'array' then new.snapshot -> 'groups' else '[]'::jsonb end) g,
                         jsonb_array_elements(case when jsonb_typeof(g -> 'items') = 'array' then g -> 'items' else '[]'::jsonb end) i
            where coalesce(i ->> 'stock', '') ~ '^[0-9a-f-]{36}$' loop
    sid := (it ->> 'stock')::uuid;
    if not exists (select 1 from public.stock_items where id = sid) then continue; end if;
    a := new.answers -> (it ->> 'id');
    if a is null or jsonb_typeof(a -> 'n') <> 'number' then
      delete from public.stock_counts where run_id = new.id and item_id = sid;
      continue;
    end if;
    v := (a ->> 'n')::numeric;
    if v < 0 or v > 1000000 then continue; end if;
    insert into public.stock_counts (item_id, value, run_id, plan_id, plan_title, user_id, user_name, period, at)
    values (sid, v, new.id, new.plan_id, left(new.snapshot ->> 'title', 200), new.user_id, nullif(nm, ''), new.period, now())
    on conflict (run_id, item_id) do update
      set value = excluded.value, at = case when stock_counts.value is distinct from excluded.value then now() else stock_counts.at end;
  end loop;
  return new;
end $$;
drop trigger if exists stock_counts_from_run on public.work_plan_runs;
create trigger stock_counts_from_run after insert or update on public.work_plan_runs
  for each row execute function public.stock_counts_from_run();

notify pgrst, 'reload schema';

-- ============================================================
-- UTA kortelių dublikatų sujungimas
-- Naujos UTA ataskaitos („Detali specifikacija“) kortelės numerį rašo su kontroliniu skaitmeniu
-- (706000 949837 0046 9), senosios – be jo (…0046). Tai ta pati kortelė: p_drop sujungiama į p_keep –
-- pylimai, PIN, priskyrimas (jei p_keep nepriskirta), pavadinimas; tie patys pylimai (ta pati diena,
-- kiekis ir suma) iš abiejų ataskaitų lieka vieną kartą. p_keep gauna pilną (ilgesnį) numerį.
-- Reikia: uta.sql, uta_pins.sql. Saugu paleisti pakartotinai.
-- ============================================================

-- the work itself (no rights check: called by the RPC below and by this script)
create or replace function public.uta_cards_merge_do(p_keep uuid, p_drop uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare k public.uta_cards; d public.uta_cards; moved int := 0; dups int := 0; no text;
begin
  if p_keep = p_drop then raise exception 'same card'; end if;
  select * into k from public.uta_cards where id = p_keep for update;
  select * into d from public.uta_cards where id = p_drop for update;
  if k.id is null or d.id is null then raise exception 'card not found'; end if;

  -- the same fill in both reports (old and new format): the one already there stays
  with x as (
    delete from public.uta_tx t
     where t.card_id = p_drop
       and exists (select 1 from public.uta_tx o
                    where o.card_id = p_keep and o.tx_date = t.tx_date
                      and round(coalesce(o.quantity, 0), 2) = round(coalesce(t.quantity, 0), 2)
                      and round(coalesce(o.amount_gross, o.amount_net, 0), 2) = round(coalesce(t.amount_gross, t.amount_net, 0), 2)
                      and lower(coalesce(o.product, '')) = lower(coalesce(t.product, '')))
    returning 1)
  select count(*) into dups from x;
  update public.uta_tx set card_id = p_keep where card_id = p_drop;
  get diagnostics moved = row_count;

  -- PIN: the kept card's own, else the other's
  if exists (select 1 from public.uta_pins where card_id = p_drop) and not exists (select 1 from public.uta_pins where card_id = p_keep) then
    update public.uta_pins set card_id = p_keep where card_id = p_drop;
  end if;

  no := case when length(regexp_replace(d.card_no, '[^0-9]', '', 'g')) > length(regexp_replace(k.card_no, '[^0-9]', '', 'g')) then d.card_no else k.card_no end;
  delete from public.uta_cards where id = p_drop;
  update public.uta_cards set
    card_no      = no,
    title        = case when coalesce(k.title, '') = '' then d.title else k.title end,
    assign_kind  = case when k.assign_kind = 'none' then d.assign_kind else k.assign_kind end,
    vehicle_id   = case when k.assign_kind = 'none' then d.vehicle_id else k.vehicle_id end,
    vehicle_name = case when k.assign_kind = 'none' then d.vehicle_name else k.vehicle_name end,
    person_id    = case when k.assign_kind = 'none' then d.person_id else k.person_id end,
    person_name  = case when k.assign_kind = 'none' then d.person_name else k.person_name end,
    valid_until  = coalesce(k.valid_until, d.valid_until),
    shared       = k.shared or d.shared,
    active       = k.active or d.active,
    updated_at   = now()
  where id = p_keep;
  return jsonb_build_object('moved', moved, 'duplicates', dups, 'card_no', no);
end $$;
revoke all on function public.uta_cards_merge_do(uuid, uuid) from public, anon, authenticated;

create or replace function public.uta_cards_merge(p_keep uuid, p_drop uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  if not public.can_edit('fleet') then raise exception 'not allowed'; end if;
  return public.uta_cards_merge_do(p_keep, p_drop);
end $$;
revoke all on function public.uta_cards_merge(uuid, uuid) from public, anon;
grant execute on function public.uta_cards_merge(uuid, uuid) to authenticated;

-- all such pairs now: one number is the other plus the last check digit; the card given to someone
-- (or the older one) stays
do $$
declare r record; n int := 0;
begin
  for r in
    select distinct on (least(a.id::text, b.id::text), greatest(a.id::text, b.id::text))
           case when (a.assign_kind <> 'none') <> (b.assign_kind <> 'none') then case when a.assign_kind <> 'none' then a.id else b.id end
                when a.created_at <= b.created_at then a.id else b.id end as keep,
           case when (a.assign_kind <> 'none') <> (b.assign_kind <> 'none') then case when a.assign_kind <> 'none' then b.id else a.id end
                when a.created_at <= b.created_at then b.id else a.id end as drop
      from public.uta_cards a
      join public.uta_cards b on a.id <> b.id
       and length(regexp_replace(a.card_no, '[^0-9]', '', 'g')) >= 12
       and length(regexp_replace(b.card_no, '[^0-9]', '', 'g')) = length(regexp_replace(a.card_no, '[^0-9]', '', 'g')) + 1
       and left(regexp_replace(b.card_no, '[^0-9]', '', 'g'), length(regexp_replace(a.card_no, '[^0-9]', '', 'g'))) = regexp_replace(a.card_no, '[^0-9]', '', 'g')
  loop
    if exists (select 1 from public.uta_cards where id = r.keep) and exists (select 1 from public.uta_cards where id = r.drop) then
      perform public.uta_cards_merge_do(r.keep, r.drop); n := n + 1;
    end if;
  end loop;
  raise notice 'UTA kortelių sujungta: %', n;
end $$;

notify pgrst, 'reload schema';

-- ============================================================
-- UTA kortelių dublikatų sujungimas
-- Naujos UTA ataskaitos („Detali specifikacija“) kortelės numerį rašo su kontroliniu skaitmeniu
-- (706000 949837 0046 9), senosios – be jo arba tik paskutinius skaitmenis (0046). Tai ta pati kortelė: p_drop sujungiama į p_keep –
-- pylimai, PIN, priskyrimas (jei p_keep nepriskirta), pavadinimas; tie patys pylimai (ta pati diena,
-- kiekis ir suma) iš abiejų ataskaitų lieka vieną kartą. p_keep gauna pilną (ilgesnį) numerį.
-- Reikia: uta.sql, uta_pins.sql. Saugu paleisti pakartotinai.
-- ============================================================

-- the work itself (no rights check: called by the RPC below and by this script)
create or replace function public.uta_cards_merge_do(p_keep uuid, p_drop uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare k public.uta_cards; d public.uta_cards; moved int := 0; dups int := 0; no text;
begin
  if p_keep = p_drop then raise exception 'same card'; end if;
  select * into k from public.uta_cards where id = p_keep for update;
  select * into d from public.uta_cards where id = p_drop for update;
  if k.id is null or d.id is null then raise exception 'card not found'; end if;

  -- the same fill in both reports (old and new format): the one already there stays
  with x as (
    delete from public.uta_tx t
     where t.card_id = p_drop
       and exists (select 1 from public.uta_tx o
                    where o.card_id = p_keep and o.tx_date = t.tx_date
                      and round(coalesce(o.quantity, 0), 2) = round(coalesce(t.quantity, 0), 2)
                      and round(coalesce(o.amount_gross, o.amount_net, 0), 2) = round(coalesce(t.amount_gross, t.amount_net, 0), 2)
                      and lower(coalesce(o.product, '')) = lower(coalesce(t.product, '')))
    returning 1)
  select count(*) into dups from x;
  update public.uta_tx set card_id = p_keep where card_id = p_drop;
  get diagnostics moved = row_count;

  -- PIN: the kept card's own, else the other's
  if exists (select 1 from public.uta_pins where card_id = p_drop) and not exists (select 1 from public.uta_pins where card_id = p_keep) then
    update public.uta_pins set card_id = p_keep where card_id = p_drop;
  end if;

  no := case when length(regexp_replace(d.card_no, '[^0-9]', '', 'g')) > length(regexp_replace(k.card_no, '[^0-9]', '', 'g')) then d.card_no else k.card_no end;
  delete from public.uta_cards where id = p_drop;
  update public.uta_cards set
    card_no      = no,
    title        = case when coalesce(k.title, '') = '' then d.title else k.title end,
    assign_kind  = case when k.assign_kind = 'none' then d.assign_kind else k.assign_kind end,
    vehicle_id   = case when k.assign_kind = 'none' then d.vehicle_id else k.vehicle_id end,
    vehicle_name = case when k.assign_kind = 'none' then d.vehicle_name else k.vehicle_name end,
    person_id    = case when k.assign_kind = 'none' then d.person_id else k.person_id end,
    person_name  = case when k.assign_kind = 'none' then d.person_name else k.person_name end,
    valid_until  = coalesce(k.valid_until, d.valid_until),
    shared       = k.shared or d.shared,
    active       = k.active or d.active,
    updated_at   = now()
  where id = p_keep;
  return jsonb_build_object('moved', moved, 'duplicates', dups, 'card_no', no);
end $$;
revoke all on function public.uta_cards_merge_do(uuid, uuid) from public, anon, authenticated;

create or replace function public.uta_cards_merge(p_keep uuid, p_drop uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  if not public.can_edit('fleet') then raise exception 'not allowed'; end if;
  return public.uta_cards_merge_do(p_keep, p_drop);
end $$;
revoke all on function public.uta_cards_merge(uuid, uuid) from public, anon;
grant execute on function public.uta_cards_merge(uuid, uuid) to authenticated;

-- all such pairs now. New reports: the whole number with the check digit (706000 949837 0046 9); older ones:
-- the whole number without it (7060009498370046) or only its last digits (0046 – when just one card fits).
-- The card given to someone (or the older one) stays.
do $$
declare r record; n int := 0; done int; k int := 0;
begin
  loop   -- again until nothing is left (a merged card may have another pair)
  done := 0; k := k + 1;
  for r in
    with c as (select id, assign_kind, created_at, regexp_replace(card_no, '[^0-9]', '', 'g') d from public.uta_cards),
    p as (
      select a.id aid, b.id bid, a.assign_kind ak, b.assign_kind bk, a.created_at ac, b.created_at bc
        from c a join c b on a.id <> b.id and a.d <> b.d and length(b.d) >= 12 and (
             (length(a.d) >= 12 and length(b.d) = length(a.d) + 1 and left(b.d, length(a.d)) = a.d)
          or (length(a.d) between 4 and 8 and right(left(b.d, length(b.d) - 1), length(a.d)) = a.d
              and (select count(*) from c x where length(x.d) >= 12 and right(left(x.d, length(x.d) - 1), length(a.d)) = a.d) = 1)))
    select case when (ak <> 'none') <> (bk <> 'none') then case when ak <> 'none' then aid else bid end when ac <= bc then aid else bid end as keep,
           case when (ak <> 'none') <> (bk <> 'none') then case when ak <> 'none' then bid else aid end when ac <= bc then bid else aid end as drop
      from p
  loop
    if exists (select 1 from public.uta_cards where id = r.keep) and exists (select 1 from public.uta_cards where id = r.drop) then
      perform public.uta_cards_merge_do(r.keep, r.drop); n := n + 1; done := done + 1;
      exit;
    end if;
  end loop;
  exit when done = 0 or k > 500;
  end loop;
  raise notice 'UTA kortelių sujungta: %', n;
end $$;

notify pgrst, 'reload schema';

-- ============================================================
-- Išlaidos → Kuras: tikslas – darbo ar asmeninis
--  * purpose 'work' (numatyta) – darbo išlaida, kaip iki šiol (komentaras būtinas, gali būti kompensuojama)
--  * purpose 'personal' – asmeniniais tikslais: nepagrindžia darbo pylimo; mokėta UTA kortele –
--    pylimas pažymimas asmeniniu (uta_personal) ir atimamas iš balanso
-- Reikia: expenses.sql. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.expenses add column if not exists purpose text not null default 'work';
do $$ begin
  alter table public.expenses add constraint expenses_purpose_check check (purpose in ('work', 'personal'));
exception when duplicate_object then null; end $$;
notify pgrst, 'reload schema';

-- ============================================================
-- Automobilio pavadinimas su valst. nr. – numeris tik vieną kartą
-- Dažnai numeris jau yra pavadinime („Iveco Daily MPL 840“) – tada „(MPL 840)“ nebepridedamas
-- (QR pranešimai, įvykiai ir kuro pylimai: chate ir automobilio istorijoje).
-- Funkcijos tos pačios kaip vehicle_fuel.sql, pakeistas tik pavadinimo sudarymas.
-- Reikia: vehicle_fuel.sql. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.vehicle_label(p_name text, p_plate text) returns text
  language sql immutable set search_path = public as $$
  select coalesce(nullif(trim(p_name), ''), 'Automobilis')
      || case when nullif(regexp_replace(upper(coalesce(p_plate, '')), '[^0-9A-Z]', '', 'g'), '') is null
                or position(regexp_replace(upper(p_plate), '[^0-9A-Z]', '', 'g') in regexp_replace(upper(coalesce(p_name, '')), '[^0-9A-Z]', '', 'g')) > 0
              then '' else ' (' || trim(p_plate) || ')' end
$$;
grant execute on function public.vehicle_label(text, text) to anon, authenticated;

drop function if exists public.vehicle_public_report(text, text, text, text, text[], jsonb);
create or replace function public.vehicle_public_report(p_token text, p_name text, p_text text, p_severity text, p_files text[], p_loc jsonb default null, p_email text default null)
  returns uuid language plpgsql security definer set search_path = public as $$
declare loc jsonb := public.vehicle_loc_clean(p_loc); v jsonb; vid text; cid uuid; who text; em text; member boolean := false; sender uuid; rid uuid := gen_random_uuid();
        att jsonb := '[]'::jsonb; f text; vname text; sev text := coalesce(nullif(p_severity, ''), 'soon'); mid uuid; nv int := 0;
begin
  v := public.vehicle_by_token(p_token);
  if v is null then raise exception 'QR kodas nebegalioja.'; end if;
  vid := v ->> 'id';
  vname := public.vehicle_label(v ->> 'name', v ->> 'plate');
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
  vname := public.vehicle_label(v ->> 'name', v ->> 'plate');
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

-- ============================================================
-- „Kuro kortelė“ renginio laiške: vairuotojas atsidaro nuorodą, nufotografuoja UTA kortelės
-- priekį ir galą – funkcija „uta-pin“ nuskaito kortelės numerį ir parodo jos PIN.
--  * uta_pin_links – nuoroda vienam renginiui: galioja renginio dienomis (diena prieš ir po),
--    tik to renginio automobilių kortelėms (card_ids; tuščia – visoms aktyvioms kortelėms)
--  * uta_pin_views – kas, kada ir kurios kortelės PIN žiūrėjo (ir nepavykę bandymai)
-- PIN pačios nuorodos niekada nerodo – tik „uta-pin“ (service role), kai nuotraukoje rasta kortelė.
-- Reikia: uta.sql, uta_pins.sql. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.uta_pin_links (
  token      text primary key,
  event_id   text not null unique,
  event_name text,
  card_ids   uuid[] not null default '{}',
  valid_from date not null,
  valid_to   date not null,
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.uta_pin_views (
  id        bigserial primary key,
  token     text,
  event_name text,
  card_id   uuid,
  card_read text,
  ok        boolean not null default false,
  reason    text,
  at        timestamptz not null default now()
);
create index if not exists uta_pin_views_token on public.uta_pin_views (token, at desc);

alter table public.uta_pin_links enable row level security;
alter table public.uta_pin_views enable row level security;
drop policy if exists "uta pin links view" on public.uta_pin_links;
create policy "uta pin links view" on public.uta_pin_links for select to authenticated using (public.can_edit('fleet') or public.can_edit('events'));
drop policy if exists "uta pin views view" on public.uta_pin_views;
create policy "uta pin views view" on public.uta_pin_views for select to authenticated using (public.can_edit('fleet'));
revoke all on public.uta_pin_links, public.uta_pin_views from anon;
grant select on public.uta_pin_links, public.uta_pin_views to authenticated;

-- the link of an event (made once, later only its days and cards change): who sends the event letter
create or replace function public.uta_pin_link_make(p_event text, p_name text, p_cards uuid[], p_from date, p_to date)
returns text language plpgsql security definer set search_path = public as $$
declare t text;
begin
  if not (public.can_edit('events') or public.can_edit('fleet')) then raise exception 'not allowed'; end if;
  if coalesce(p_event, '') = '' or p_from is null or p_to is null or p_to < p_from or p_to - p_from > 60 then raise exception 'bad dates'; end if;
  select token into t from public.uta_pin_links where event_id = p_event;
  if t is null then
    t := encode(extensions.gen_random_bytes(18), 'hex');
    insert into public.uta_pin_links (token, event_id, event_name, card_ids, valid_from, valid_to)
    values (t, p_event, left(p_name, 200), coalesce(p_cards, '{}'), p_from, p_to);
  else
    update public.uta_pin_links set event_name = left(p_name, 200), card_ids = coalesce(p_cards, '{}'), valid_from = p_from, valid_to = p_to, updated_at = now()
     where token = t;
  end if;
  return t;
end $$;
revoke all on function public.uta_pin_link_make(text, text, uuid[], date, date) from public, anon;
grant execute on function public.uta_pin_link_make(text, text, uuid[], date, date) to authenticated;

-- the page asks only whether the link works (and for which event) – nothing about cards or PINs
create or replace function public.uta_pin_link_info(p_token text)
returns jsonb language sql stable security definer set search_path = public as $$
  select case when l.token is null then jsonb_build_object('ok', false, 'why', 'none')
              when (now() at time zone 'Europe/Vilnius')::date < l.valid_from - 1 then jsonb_build_object('ok', false, 'why', 'early', 'from', l.valid_from - 1, 'event', l.event_name)
              when (now() at time zone 'Europe/Vilnius')::date > l.valid_to + 1 then jsonb_build_object('ok', false, 'why', 'late', 'event', l.event_name)
              else jsonb_build_object('ok', true, 'event', l.event_name, 'to', l.valid_to + 1) end
    from (select 1) x left join public.uta_pin_links l on l.token = p_token
$$;
revoke all on function public.uta_pin_link_info(text) from public;
grant execute on function public.uta_pin_link_info(text) to anon, authenticated;

notify pgrst, 'reload schema';

-- ============================================================
-- „Kuro kortelė“ renginio laiške: vairuotojas atsidaro nuorodą, nufotografuoja UTA kortelės
-- priekį ir galą – funkcija „uta-pin“ nuskaito kortelės numerį ir parodo jos PIN.
--  * uta_pin_links – nuoroda vienam renginiui: galioja renginio dienomis (diena prieš ir po),
--    tik to renginio automobilių kortelėms (card_ids; tuščia – visoms aktyvioms kortelėms)
--  * uta_pin_views – kas, kada ir kurios kortelės PIN žiūrėjo (ir nepavykę bandymai)
-- PIN pačios nuorodos niekada nerodo – tik „uta-pin“ (service role), kai nuotraukoje rasta kortelė.
-- Reikia: uta.sql, uta_pins.sql. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.uta_pin_links (
  token      text primary key,
  event_id   text not null unique,
  event_name text,
  card_ids   uuid[] not null default '{}',
  valid_from date not null,
  valid_to   date not null,
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.uta_pin_views (
  id        bigserial primary key,
  token     text,
  event_name text,
  card_id   uuid,
  card_read text,
  ok        boolean not null default false,
  reason    text,
  at        timestamptz not null default now()
);
create index if not exists uta_pin_views_token on public.uta_pin_views (token, at desc);
-- who (the name typed on the page), where (the phone's place) – with the time it is the fill's „when“ in the UTA reports
alter table public.uta_pin_views add column if not exists driver_name text;
alter table public.uta_pin_views add column if not exists lat double precision;
alter table public.uta_pin_views add column if not exists lng double precision;
alter table public.uta_pin_views add column if not exists acc integer;
alter table public.uta_pin_views add column if not exists vehicle text;
create index if not exists uta_pin_views_card on public.uta_pin_views (card_id, at desc);

alter table public.uta_pin_links enable row level security;
alter table public.uta_pin_views enable row level security;
drop policy if exists "uta pin links view" on public.uta_pin_links;
create policy "uta pin links view" on public.uta_pin_links for select to authenticated using (public.can_edit('fleet') or public.can_edit('events'));
drop policy if exists "uta pin views view" on public.uta_pin_views;
create policy "uta pin views view" on public.uta_pin_views for select to authenticated using (public.can_view('fleet') or public.can_view('stats'));
revoke all on public.uta_pin_links, public.uta_pin_views from anon;
grant select on public.uta_pin_links, public.uta_pin_views to authenticated;

-- the link of an event (made once, later only its days and cards change): who sends the event letter
create or replace function public.uta_pin_link_make(p_event text, p_name text, p_cards uuid[], p_from date, p_to date)
returns text language plpgsql security definer set search_path = public as $$
declare t text;
begin
  if not (public.can_edit('events') or public.can_edit('fleet')) then raise exception 'not allowed'; end if;
  if coalesce(p_event, '') = '' or p_from is null or p_to is null or p_to < p_from or p_to - p_from > 60 then raise exception 'bad dates'; end if;
  select token into t from public.uta_pin_links where event_id = p_event;
  if t is null then
    t := encode(extensions.gen_random_bytes(18), 'hex');
    insert into public.uta_pin_links (token, event_id, event_name, card_ids, valid_from, valid_to)
    values (t, p_event, left(p_name, 200), coalesce(p_cards, '{}'), p_from, p_to);
  else
    update public.uta_pin_links set event_name = left(p_name, 200), card_ids = coalesce(p_cards, '{}'), valid_from = p_from, valid_to = p_to, updated_at = now()
     where token = t;
  end if;
  return t;
end $$;
revoke all on function public.uta_pin_link_make(text, text, uuid[], date, date) from public, anon;
grant execute on function public.uta_pin_link_make(text, text, uuid[], date, date) to authenticated;

-- the page asks only whether the link works (and for which event) – nothing about cards or PINs
create or replace function public.uta_pin_link_info(p_token text)
returns jsonb language sql stable security definer set search_path = public as $$
  select case when l.token is null then jsonb_build_object('ok', false, 'why', 'none')
              when (now() at time zone 'Europe/Vilnius')::date < l.valid_from - 1 then jsonb_build_object('ok', false, 'why', 'early', 'from', l.valid_from - 1, 'event', l.event_name)
              when (now() at time zone 'Europe/Vilnius')::date > l.valid_to + 1 then jsonb_build_object('ok', false, 'why', 'late', 'event', l.event_name)
              else jsonb_build_object('ok', true, 'event', l.event_name, 'to', l.valid_to + 1) end
    from (select 1) x left join public.uta_pin_links l on l.token = p_token
$$;
revoke all on function public.uta_pin_link_info(text) from public;
grant execute on function public.uta_pin_link_info(text) to anon, authenticated;

notify pgrst, 'reload schema';

-- ============================================================
-- UTA kortelės CVC (3 skaičiai kortelės gale) – „Kuro kortelė“ renginio laiške: vairuotojas įrašo
-- paskutinius 5 kortelės skaitmenis ir CVC, funkcija „uta-pin“ juos patikrina ir parodo PIN.
-- CVC mato ir keičia tik redaguojantys „Transportą“ (Transportas → UTA kortelės → kortelė);
-- funkcija jį skaito su service role. Reikia: uta.sql. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.uta_card_cvc (
  card_id    uuid primary key references public.uta_cards(id) on delete cascade,
  cvc        text not null check (cvc ~ '^[0-9]{3,4}$'),
  updated_by uuid default auth.uid(),
  updated_at timestamptz not null default now()
);
alter table public.uta_card_cvc enable row level security;
drop policy if exists "uta cvc edit" on public.uta_card_cvc;
create policy "uta cvc edit" on public.uta_card_cvc for all to authenticated
  using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
revoke all on public.uta_card_cvc from anon;
grant select, insert, update, delete on public.uta_card_cvc to authenticated;
notify pgrst, 'reload schema';

-- ============================================================
-- Išlaidos: balansas asmeninėms reikmėms – tik eurais
-- (pvz. 200 € per mėnesį; asmeniniai UTA pylimai atimami jų suma eurais; nepanaudotas likutis pereina
-- į kitą mėnesį, viršytas – atimamas iš kito). Anksčiau litrais nustatyti balansai ir pažymėti
-- asmeniniai pylimai perjungiami į eurus (balanso skaičius lieka tas pats – patikrink, ar tinka).
-- Reikia: expenses_rules.sql, expenses_liters.sql. Saugu paleisti pakartotinai.
-- ============================================================
update public.expense_allowance set unit = 'eur' where unit is distinct from 'eur';
update public.uta_personal set unit = 'eur' where unit is distinct from 'eur';
alter table public.expense_allowance alter column unit set default 'eur';
alter table public.uta_personal alter column unit set default 'eur';
notify pgrst, 'reload schema';

-- ============================================================
-- UTA kortelės kodas – skaičiai kortelės gale po „CVC:“ – „Kuro kortelė“ renginio laiške: vairuotojas
-- juos nurašo, funkcija „uta-pin“ randa tą kortelę tarp renginio kortelių ir parodo PIN.
-- CVC mato ir keičia tik redaguojantys „Transportą“ (Transportas → UTA kortelės → kortelė);
-- funkcija jį skaito su service role. Reikia: uta.sql. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.uta_card_cvc (
  card_id    uuid primary key references public.uta_cards(id) on delete cascade,
  cvc        text not null,
  updated_by uuid default auth.uid(),
  updated_at timestamptz not null default now()
);
alter table public.uta_card_cvc drop constraint if exists uta_card_cvc_cvc_check;
alter table public.uta_card_cvc add constraint uta_card_cvc_cvc_check check (cvc ~ '^[0-9]{3,8}$');
alter table public.uta_card_cvc enable row level security;
drop policy if exists "uta cvc edit" on public.uta_card_cvc;
create policy "uta cvc edit" on public.uta_card_cvc for all to authenticated
  using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
revoke all on public.uta_card_cvc from anon;
grant select, insert, update, delete on public.uta_card_cvc to authenticated;
notify pgrst, 'reload schema';

-- ============================================================
-- „Kuro kortelė“ → UTA pylimas
-- Vairuotojas telefone nurašo skaičius po „CVC:“ ir pamato PIN – tai įvykis (uta_pin_views).
-- Įkėlus UTA ataskaitą jis susiejamas su tos kortelės pylimu (uta_pin_views.tx_id):
--  * ataskaitoje su laiku – artimiausias pylimas nuo 30 min. prieš iki 6 val. po PIN peržiūros;
--  * ataskaitoje be laiko (PDF) – tos pačios dienos (ar kitos dienos, jei PIN žiūrėtas vakare) pylimas.
-- Kelios to paties žmogaus peržiūros per 2 val. – tas pats pylimas. Ištrynus ataskaitą ryšys dingsta,
-- įkėlus vėl – susiejama iš naujo. Nesusietos peržiūros rodomos UTA puslapyje ir Ataskaitose.
-- Reikia: uta.sql, uta_pin_links.sql. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.uta_pin_views add column if not exists tx_id uuid references public.uta_tx(id) on delete set null;
create index if not exists uta_pin_views_tx on public.uta_pin_views (tx_id);

-- the work: every PIN view not yet joined to a fill (last 400 days)
create or replace function public.uta_pin_link_fills_do()
returns integer language plpgsql security definer set search_path = public as $$
declare v record; t uuid; n int := 0;
begin
  for v in select id, card_id, at, driver_name from public.uta_pin_views
            where ok and card_id is not null and tx_id is null and at > now() - interval '400 days'
            order by at loop
    -- the same person's view of the same card a little earlier: the same fill
    select p.tx_id into t from public.uta_pin_views p
     where p.card_id = v.card_id and p.tx_id is not null and p.id <> v.id
       and p.at between v.at - interval '2 hours' and v.at
       and lower(coalesce(p.driver_name, '')) = lower(coalesce(v.driver_name, ''))
     order by p.at desc limit 1;
    if t is null then
      select x.id into t from public.uta_tx x
       where x.card_id = v.card_id and coalesce(x.quantity, 0) > 0
         and not exists (select 1 from public.uta_pin_views o where o.tx_id = x.id and abs(extract(epoch from o.at - v.at)) > 7200)
         and (case when (x.tx_at at time zone 'Europe/Vilnius')::time <> '00:00'
                   then x.tx_at between v.at - interval '30 minutes' and v.at + interval '6 hours'
                   else x.tx_date = (v.at at time zone 'Europe/Vilnius')::date
                     or (x.tx_date = (v.at at time zone 'Europe/Vilnius')::date + 1 and (v.at at time zone 'Europe/Vilnius')::time >= '18:00') end)
       order by case when (x.tx_at at time zone 'Europe/Vilnius')::time <> '00:00' then abs(extract(epoch from x.tx_at - v.at)) else 0 end,
                (x.tx_date <> (v.at at time zone 'Europe/Vilnius')::date), x.tx_at, x.id
       limit 1;
    end if;
    if t is not null then update public.uta_pin_views set tx_id = t where id = v.id; n := n + 1; end if;
  end loop;
  return n;
end $$;
revoke all on function public.uta_pin_link_fills_do() from public, anon, authenticated;

-- after a report is loaded (or a fill moved to another card): joined by itself
create or replace function public.uta_pin_link_fills_trg() returns trigger
  language plpgsql security definer set search_path = public as $$
begin perform public.uta_pin_link_fills_do(); return null; end $$;
drop trigger if exists uta_pin_link_fills on public.uta_tx;
create trigger uta_pin_link_fills after insert or update of card_id on public.uta_tx
  for each statement execute function public.uta_pin_link_fills_trg();

-- the page asks after an upload: how many joined, how many views of that time have no fill
create or replace function public.uta_pin_link_fills(p_from date default null, p_to date default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare n int; last date; ok int; open int;
begin
  if not public.can_view('fleet') then raise exception 'not allowed'; end if;
  n := public.uta_pin_link_fills_do();
  select max(tx_date) into last from public.uta_tx;
  select count(*) filter (where v.tx_id is not null),
         count(*) filter (where v.tx_id is null and (v.at at time zone 'Europe/Vilnius')::date <= coalesce(last, '1900-01-01'))
    into ok, open
    from public.uta_pin_views v
   where v.ok
     and (p_from is null or (v.at at time zone 'Europe/Vilnius')::date >= p_from)
     and (p_to is null or (v.at at time zone 'Europe/Vilnius')::date <= p_to);
  return jsonb_build_object('linked', ok, 'unlinked', open, 'new', n, 'last', last);
end $$;
revoke all on function public.uta_pin_link_fills(date, date) from public, anon;
grant execute on function public.uta_pin_link_fills(date, date) to authenticated;

-- cards joined (uta_merge.sql): their PIN views go along
create or replace function public.uta_pin_views_card_move() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if new.card_id is distinct from old.card_id and old.card_id is not null and new.card_id is not null
     and not exists (select 1 from public.uta_tx where card_id = old.card_id) then
    update public.uta_pin_views set card_id = new.card_id where card_id = old.card_id;
  end if;
  return null;
end $$;
drop trigger if exists uta_pin_views_card_move on public.uta_tx;
create trigger uta_pin_views_card_move after update of card_id on public.uta_tx
  for each row execute function public.uta_pin_views_card_move();

-- the views loaded so far
select public.uta_pin_link_fills_do();

notify pgrst, 'reload schema';

-- ============================================================
-- QR kodas ant automobilio → „Kuro pylimas“ → tam automobiliui priskirtos UTA kortelės PIN
--  * įmonės narys, prisijungęs programėlėje ar telefono naršyklėje – PIN rodomas iš karto, kodo nereikia;
--  * ne narys – įrašo savo vairuotojo kodą (4 skaitmenys) iš renginio laiško; kodas turi būti
--    priskirtas šiam automobiliui renginyje tą dieną (diena prieš ar po – irgi tinka). Jei automobilis
--    tomis dienomis jokiame renginyje nepriskirtas – tinka bet kuris galiojantis vairuotojo kodas.
--  * kiekviena peržiūra įrašoma į uta_pin_views (kas, kada, kur, kuri kortelė, renginys) – UTA
--    ataskaitose, o įkėlus UTA ataskaitą susiejama su pylimu (uta_pin_fills.sql).
--  * vehicle_drivers – kas kurią dieną kuriuo įmonės automobiliu važiuoja (pildo programa iš renginių
--    skilties „Transportas“; FURA ir nuomoto transporto vairuotojų čia nėra – jiems kodo nereikia).
-- 5 neteisingi kodai per parą – kuro PIN šiam automobiliui užrakinamas parai (nariams – ne).
-- Reikia: vehicle_qr.sql, driver_codes.sql, uta.sql, uta_pins.sql, uta_pin_links.sql. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.vehicle_drivers (
  event_id    text not null,
  day         date not null,
  vehicle_id  text not null,
  driver_key  text not null,
  driver_name text,
  event_name  text,
  updated_at  timestamptz not null default now(),
  primary key (event_id, day, vehicle_id, driver_key)
);
create index if not exists vehicle_drivers_veh on public.vehicle_drivers (vehicle_id, day);
alter table public.vehicle_drivers enable row level security;
drop policy if exists "vehicle drivers view" on public.vehicle_drivers;
create policy "vehicle drivers view" on public.vehicle_drivers for select to authenticated using (public.can_view('fleet') or public.can_view('events'));
revoke all on public.vehicle_drivers from anon;
grant select on public.vehicle_drivers to authenticated;

-- an event's drivers of company vehicles: p_rows [{ "d":"2026-10-14", "v":"veh_…", "k":"jonas jonaitis", "n":"Jonas Jonaitis" }]
create or replace function public.vehicle_drivers_set(p_event text, p_name text, p_rows jsonb)
returns integer language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if not public.can_edit('events') then raise exception 'not allowed'; end if;
  if coalesce(p_event, '') = '' then raise exception 'no event'; end if;
  delete from public.vehicle_drivers where event_id = p_event;
  insert into public.vehicle_drivers (event_id, day, vehicle_id, driver_key, driver_name, event_name)
  select distinct on (x->>'d', x->>'v', lower(trim(x->>'k'))) p_event, (x->>'d')::date, x->>'v', lower(trim(x->>'k')), left(trim(x->>'n'), 120), left(p_name, 200)
    from jsonb_array_elements(case when jsonb_typeof(p_rows) = 'array' then p_rows else '[]'::jsonb end) x
   where coalesce(x->>'d', '') ~ '^\d{4}-\d{2}-\d{2}$' and coalesce(x->>'v', '') <> '' and coalesce(trim(x->>'k'), '') <> ''
   limit 500;
  get diagnostics n = row_count;
  return n;
end $$;
revoke all on function public.vehicle_drivers_set(text, text, jsonb) from public, anon;
grant execute on function public.vehicle_drivers_set(text, text, jsonb) to authenticated;

create or replace function public.uta_card_mask(no text) returns text language sql immutable as $$
  select case when array_length(g, 1) >= 3 then '•••• ' || g[array_length(g, 1) - 1] || ' ' || g[array_length(g, 1)]
              else '•••• ' || right(regexp_replace(no, '[^0-9]', '', 'g'), 6) end
    from (select regexp_split_to_array(trim(coalesce(no, '')), '\s+') g) s
$$;

-- the QR page: the PIN of the vehicle's card(s)
create or replace function public.uta_vehicle_pin(p_token text, p_code text default null, p_loc jsonb default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v jsonb; vid text; vname text; tok text; who text; ev text; member boolean := false;
        d date := (now() at time zone 'Europe/Vilnius')::date; lat double precision; lng double precision; acc int;
        out jsonb := '[]'::jsonb; c record; cd text := nullif(regexp_replace(coalesce(p_code, ''), '\D', '', 'g'), ''); dkey text; dname text;
begin
  v := public.vehicle_by_token(p_token);
  if v is null then raise exception 'QR kodas nebegalioja.'; end if;
  vid := v ->> 'id'; tok := 'qr:' || vid;
  vname := concat_ws(' · ', nullif(v ->> 'name', ''), case when nullif(v ->> 'plate', '') is not null
             and position(upper(regexp_replace(v ->> 'plate', '[^0-9A-Za-z]', '', 'g')) in upper(regexp_replace(coalesce(v ->> 'name', ''), '[^0-9A-Za-z]', '', 'g'))) = 0
             then v ->> 'plate' end);
  begin
    lat := (p_loc ->> 'lat')::double precision; lng := (p_loc ->> 'lng')::double precision; acc := round((p_loc ->> 'acc')::numeric)::int;
    if lat not between -90 and 90 or lng not between -180 and 180 then lat := null; lng := null; acc := null; end if;
  exception when others then lat := null; lng := null; acc := null; end;

  if auth.uid() is not null and public.is_approved() then
    member := true; who := public.my_name();
    select event_name into ev from public.vehicle_drivers where vehicle_id = vid and day between d - 1 and d + 1 order by abs(day - d) limit 1;
  else
    if (select count(*) from public.uta_pin_views where token = tok and at > now() - interval '1 hour') >= 20 then
      raise exception 'Per daug bandymų – pabandyk po valandos.'; end if;
    if (select count(*) from public.uta_pin_views where token = tok and reason = 'neteisingas kodas' and at > now() - interval '24 hours') >= 5 then
      raise exception 'Per daug neteisingų kodų – kuro PIN šiam automobiliui užrakintas parai. Kreipkis į ofisą.'; end if;
    if cd is null or cd !~ '^[0-9]{4}$' then raise exception 'Įrašyk savo vairuotojo kodą (4 skaitmenys) iš renginio laiško.'; end if;
    select x.key, x.name into dkey, dname from public.driver_codes x where x.code = cd;
    if dkey is not null then
      select x.event_name into ev from public.vehicle_drivers x
       where x.vehicle_id = vid and x.driver_key = dkey and x.day between d - 1 and d + 1 order by abs(x.day - d) limit 1;
      -- the vehicle is someone else's in an event these days: not this code
      if not found and exists (select 1 from public.vehicle_drivers x where x.vehicle_id = vid and x.day between d - 1 and d + 1) then dkey := null; end if;
    end if;
    if dkey is null then
      insert into public.uta_pin_views (token, ok, reason, card_read, driver_name, lat, lng, acc, vehicle)
      values (tok, false, 'neteisingas kodas', left(cd, 2) || '••', null, lat, lng, acc, vname);
      return jsonb_build_object('error', 'Šis kodas šiam automobiliui šiandien nepriskirtas – patikrink renginio laiške.');
    end if;
    who := dname;
  end if;

  for c in select k.id, k.card_no, k.title, p.pin from public.uta_cards k left join public.uta_pins p on p.card_id = k.id
            where k.active and k.assign_kind = 'vehicle' and k.vehicle_id = vid order by k.created_at loop
    insert into public.uta_pin_views (token, event_name, card_id, ok, reason, driver_name, lat, lng, acc, vehicle)
    values (tok, ev, c.id, c.pin is not null, case when c.pin is null then 'PIN neįrašytas' end, left(who, 120), lat, lng, acc, vname);
    out := out || jsonb_build_object('card', public.uta_card_mask(c.card_no), 'title', coalesce(c.title, ''), 'pin', c.pin);
  end loop;
  return jsonb_build_object('pins', out, 'name', who, 'member', member, 'code', case when member then null else cd end, 'event', ev, 'vehicle', vname);
end $$;
revoke all on function public.uta_vehicle_pin(text, text, jsonb) from public;
grant execute on function public.uta_vehicle_pin(text, text, jsonb) to anon, authenticated;

notify pgrst, 'reload schema';
