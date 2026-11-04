-- ============================================================
-- Renginių Google Drive aplankai (serverio funkcija gdrive):
-- kiekvienam renginiui – aplankas „2026-11-05 Renginio pavadinimas“ įmonės bendrame Drive (Shared drive),
-- jame: Darbiniai planai, Video failai, Raideriai, Erdvės foto, Papildomi failai.
-- Prieiga: Office ir aukštesni (pagal el. paštą) + tie, kam išsiųstas renginio laiškas.
-- Slack: įkėlus failą renginio kanale botas paklausia „Kur dėti?“ – failas nukeliamas į pasirinktą aplanką.
-- Įjungia Super Admin (Admin → Google Drive). Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.event_drive (
  event_id    text primary key,
  folder_id   text not null,
  url         text not null default '',
  name        text not null default '',
  subs        jsonb not null default '{}'::jsonb,   -- { plans:{id,url}, video:…, riders:…, venue:…, extra:… }
  shared      text[] not null default '{}',         -- el. paštai, kuriems jau suteikta prieiga
  last_error  text,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
alter table public.event_drive enable row level security;
drop policy if exists "event drive view" on public.event_drive;
create policy "event drive view" on public.event_drive for select to authenticated using (public.can_view('events'));
revoke all on public.event_drive from anon;
grant select on public.event_drive to authenticated;

-- Slack files waiting for „Kur dėti?“ and where they went
create table if not exists public.drive_uploads (
  id          uuid primary key default gen_random_uuid(),
  event_id    text not null,
  slack_file  text not null,
  slack_ts    text,
  name        text not null default '',
  category    text,
  drive_id    text,
  drive_url   text,
  by_name     text,
  error       text,
  created_at  timestamptz not null default now(),
  done_at     timestamptz
);
create unique index if not exists drive_uploads_file on public.drive_uploads (slack_file, event_id);
alter table public.drive_uploads enable row level security;
drop policy if exists "drive uploads view" on public.drive_uploads;
create policy "drive uploads view" on public.drive_uploads for select to authenticated using (public.can_view('events'));
revoke all on public.drive_uploads from anon;
grant select on public.drive_uploads to authenticated;

notify pgrst, 'reload schema';
select 'event_drive ok' as result, (select count(*) from public.event_drive) as folders;
