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
  vehicle_cat   text,
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
alter table public.bolt_trips add column if not exists vehicle_cat text;   -- Vehicle category group (a table made before)
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
