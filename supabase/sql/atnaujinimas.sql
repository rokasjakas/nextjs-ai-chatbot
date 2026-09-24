-- ============================================================
-- EventSolutions App — VISI naujausi duomenų bazės pakeitimai viename faile
-- (chato teisės, pranešimai, el. paštas, failai chate, kalendorius,
-- narių trynimas). Supabase → SQL Editor → įklijuok VISĄ → Run.
-- Saugu paleisti kelis kartus.
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
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail'));

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
                when p.role in ('office','tech','freelance','runner') then
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
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail'));

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
