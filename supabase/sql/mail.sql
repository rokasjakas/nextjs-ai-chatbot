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
