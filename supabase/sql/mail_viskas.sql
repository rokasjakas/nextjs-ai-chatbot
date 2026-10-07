-- ============================================================
-- El. paštas per Gmail – VISKAS VIENAME (saugu paleisti pakartotinai)
--  1) mail_index + mail_sync – laiškų sąrašas duomenų bazėje (greitas sąrašas, skirtukai,
--     sinchronizavimas kas minutę ir pranešimai apie naujus laiškus)
--  2) mail_bodies – iš anksto paruoštas laiškų turinys (laiškai atsidaro iš karto)
--  3) mail_gmail – Gmail prijungimas ir Gmail skirtukai
-- Reikia: mail.sql (jau paleistas – paštas veikia).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- ============================================================

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
