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
