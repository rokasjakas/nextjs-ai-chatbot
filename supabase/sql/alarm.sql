-- ============================================================
-- Ofisas → „Signalizacija“
--  * alarm_staff_codes – darbuotojų signalizacijos kodai: mato ir keičia TIK Admin ir Office
--  * alarm_temp_codes  – laikini kodai: atsitiktinis 4 skaitmenų kodas, kam (vardas, pavardė; el. paštas nebūtinas), iki kada galioja.
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
  person_name   text,
  email         text,
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
-- (a table made before: the name added, the e-mail not needed)
alter table public.alarm_temp_codes add column if not exists person_name text;
alter table public.alarm_temp_codes alter column email drop not null;
alter table public.alarm_temp_codes drop constraint if exists alarm_temp_codes_email_check;
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
