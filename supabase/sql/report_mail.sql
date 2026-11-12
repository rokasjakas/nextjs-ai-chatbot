-- ============================================================
-- Ataskaitos → Bolt / Wolt: mėnesio ataskaitos (PDF) siuntimas
--  * report_mail – kam siųsti (el. paštai) ir automatinis siuntimas: kurią dieną (paskutinė / pirma
--    mėnesio darbo diena ar konkreti diena), kelintą valandą (Vilniaus laiku) ir kurio mėnesio ataskaitą
--    (einamojo ar praėjusio). Siunčia funkcija „reports-mail“ (ją kas 5 min. pažadina push-notify cron).
--  * last_auto – mėnuo, kurį jau išsiųsta automatiškai (kad nesikartotų); last_result – kas nutiko paskutinį kartą
-- Tvarko tik Admin. Reikia: user_roles.sql (my_role). Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.report_mail (
  kind         text primary key check (kind in ('bolt','wolt')),
  emails       text[] not null default '{}',
  auto         boolean not null default false,
  rule         text not null default 'last_workday' check (rule in ('last_workday','first_workday','day')),
  day          integer not null default 1 check (day between 1 and 31),
  hour         integer not null default 16 check (hour between 0 and 23),
  period       text not null default 'current' check (period in ('current','previous')),
  last_auto    text,
  last_sent_at timestamptz,
  last_result  text,
  updated_by   uuid default auth.uid(),
  updated_at   timestamptz not null default now()
);
insert into public.report_mail (kind) values ('bolt'), ('wolt') on conflict (kind) do nothing;
alter table public.report_mail enable row level security;
drop policy if exists "report mail admin" on public.report_mail;
create policy "report mail admin" on public.report_mail for all to authenticated
  using (public.my_role() = 'admin') with check (public.my_role() = 'admin');
revoke all on public.report_mail from anon;
grant select, insert, update on public.report_mail to authenticated;

notify pgrst, 'reload schema';
