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
