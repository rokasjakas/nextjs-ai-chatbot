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
