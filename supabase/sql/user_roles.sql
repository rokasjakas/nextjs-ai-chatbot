-- ============================================================
-- Vartotojai, prieigos lygiai ir teisės.
--
-- Kiekvienas prisiregistravęs žmogus gauna profilį su lygiu „pending“
-- (laukia patvirtinimo) ir negali nieko matyti, kol administratorius
-- nesuteikia lygio: admin, office, tech, freelance, runner (arba „blocked“).
-- Ką kiekvienas lygis gali matyti / redaguoti, laikoma lentelėje
-- role_permissions ir keičiama svetainės „Admin“ skiltyje. Šios taisyklės
-- galioja pačioje duomenų bazėje, todėl jų neapeisi pro naršyklę.
--
-- PRIEŠ PALEIDŽIANT: žemiau (1 žingsnis) įrašyk savo el. paštą — ta paskyra
-- taps pirmuoju administratoriumi. Tada Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- profiliai ----------
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  email       text not null,
  full_name   text,
  role        text not null default 'pending'
              check (role in ('pending','admin','office','tech','freelance','runner','blocked')),
  created_at  timestamptz not null default now(),
  approved_at timestamptz,
  approved_by text,
  notified_at timestamptz
);
-- Lentelė jau galėjo būti sukurta anksčiau (kitais stulpeliais): trūkstami
-- stulpeliai pridedami, esami duomenys lieka.
alter table public.profiles add column if not exists email       text;
alter table public.profiles add column if not exists full_name   text;
alter table public.profiles add column if not exists role        text not null default 'pending';
alter table public.profiles add column if not exists created_at  timestamptz not null default now();
alter table public.profiles add column if not exists approved_at timestamptz;
alter table public.profiles add column if not exists approved_by text;
alter table public.profiles add column if not exists notified_at timestamptz;
update public.profiles set role = 'pending'
  where role is null or role not in ('pending','admin','office','tech','freelance','runner','blocked');
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check
  check (role in ('pending','admin','office','tech','freelance','runner','blocked'));
create index if not exists profiles_role_idx on public.profiles (role);

-- ---------- teisės pagal lygį ----------
create table if not exists public.role_permissions (
  role     text not null check (role in ('office','tech','freelance','runner')),
  section  text not null check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats')),
  can_view boolean not null default false,
  can_edit boolean not null default false,
  primary key (role, section)
);

-- numatytosios teisės (jau esamų eilučių nekeičia)
insert into public.role_permissions (role, section, can_view, can_edit) values
  -- Office: mato viską (išskyrus Admin), redaguoja renginius, paėmimus, transportą
  ('office','events',true,true), ('office','rentals',true,true), ('office','fleet',true,true),
  ('office','projects',true,false), ('office','load',true,false), ('office','inventory',true,false),
  ('office','rules',true,false), ('office','stats',true,false),
  -- Tech: mato viską (išskyrus Admin), redaguoja paėmimus, krovimą, sandėlį, pakavimą, transportą
  ('tech','rentals',true,true), ('tech','load',true,true), ('tech','inventory',true,true),
  ('tech','rules',true,true), ('tech','fleet',true,true),
  ('tech','events',true,false), ('tech','projects',true,false), ('tech','stats',true,false),
  -- Freelance: mato tik renginius, paėmimus, projektus, krovimą
  ('freelance','events',true,false), ('freelance','rentals',true,false),
  ('freelance','projects',true,false), ('freelance','load',true,false),
  ('freelance','inventory',false,false), ('freelance','rules',false,false),
  ('freelance','fleet',false,false), ('freelance','stats',false,false),
  -- Runner: mato ir redaguoja tik paėmimus
  ('runner','rentals',true,true),
  ('runner','events',false,false), ('runner','projects',false,false), ('runner','load',false,false),
  ('runner','inventory',false,false), ('runner','rules',false,false),
  ('runner','fleet',false,false), ('runner','stats',false,false)
on conflict (role, section) do nothing;

-- ---------- pagalbinės funkcijos (naudojamos taisyklėse) ----------
create or replace function public.my_role() returns text
  language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid()
$$;

create or replace function public.is_admin() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() = 'admin', false)
$$;

create or replace function public.can_view(sec text) returns boolean
  language sql stable security definer set search_path = public as $$
  select case
    when public.my_role() = 'admin' then true
    else coalesce((select rp.can_view or rp.can_edit from public.role_permissions rp
                   where rp.role = public.my_role() and rp.section = sec), false)
  end
$$;

create or replace function public.can_edit(sec text) returns boolean
  language sql stable security definer set search_path = public as $$
  select case
    when public.my_role() = 'admin' then true
    else coalesce((select rp.can_edit from public.role_permissions rp
                   where rp.role = public.my_role() and rp.section = sec), false)
  end
$$;

create or replace function public.is_approved() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','office','tech','freelance','runner'), false)
$$;

-- kuri svetainės skiltis valdo kurį bendrų duomenų raktą (public.app_state)
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
    else public.is_admin()
  end
$$;

grant execute on function public.my_role(), public.is_admin(), public.can_view(text),
  public.can_edit(text), public.is_approved(), public.app_state_can_edit(text) to authenticated;

-- ---------- naujas vartotojas → profilis „laukia patvirtinimo“ ----------
create or replace function public.handle_new_user() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, full_name)
  values (new.id, new.email, nullif(trim(new.raw_user_meta_data ->> 'full_name'), ''))
  on conflict (id) do update set email = coalesce(public.profiles.email, excluded.email);
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- jau esamos paskyros irgi gauna profilius (laukia patvirtinimo)
insert into public.profiles (id, email, full_name)
select u.id, u.email, nullif(trim(u.raw_user_meta_data ->> 'full_name'), '')
from auth.users u
on conflict (id) do nothing;
update public.profiles p set email = u.email
from auth.users u where u.id = p.id and (p.email is null or p.email = '');

-- paskutinio administratoriaus pašalinti negalima; kas ir kada patvirtino
create or replace function public.profiles_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if old.role = 'admin' and new.role <> 'admin'
     and not exists (select 1 from public.profiles where role = 'admin' and id <> old.id) then
    raise exception 'Negalima pašalinti paskutinio administratoriaus.';
  end if;
  if new.role <> old.role and old.role = 'pending' and new.role not in ('pending','blocked') then
    new.approved_at := now();
    new.approved_by := coalesce(auth.jwt() ->> 'email', new.approved_by);
  end if;
  return new;
end $$;

drop trigger if exists profiles_guard on public.profiles;
create trigger profiles_guard before update on public.profiles
  for each row execute function public.profiles_guard();

create or replace function public.profiles_delete_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if old.role = 'admin' and not exists (select 1 from public.profiles where role = 'admin' and id <> old.id) then
    raise exception 'Negalima pašalinti paskutinio administratoriaus.';
  end if;
  return old;
end $$;

drop trigger if exists profiles_delete_guard on public.profiles;
create trigger profiles_delete_guard before delete on public.profiles
  for each row execute function public.profiles_delete_guard();

-- ---------- 1 ŽINGSNIS: pirmasis administratorius ----------
-- Pakeisk el. paštą į savo (tą, kuriuo jungiesi prie svetainės).
do $$
declare admin_email text := 'IRASYK-SAVO@EL.PASTAS';
begin
  if admin_email = 'IRASYK-SAVO@EL.PASTAS' then
    if not exists (select 1 from public.profiles where role = 'admin') then
      raise exception 'Įrašyk savo el. paštą eilutėje admin_email := ''...'' ir paleisk dar kartą.';
    end if;
  else
    update public.profiles set role = 'admin', approved_at = coalesce(approved_at, now())
    where lower(email) = lower(admin_email);
    if not found then
      raise exception 'Paskyra % nerasta. Pirma prisiregistruok svetainėje šiuo el. paštu.', admin_email;
    end if;
  end if;
end $$;

-- ---------- taisyklės (RLS) ----------
alter table public.profiles         enable row level security;
alter table public.role_permissions enable row level security;

-- ankstesnės profilių taisyklės pašalinamos (pvz. „vartotojas gali keisti savo
-- profilį“ leistų pačiam pasikeisti lygį)
do $$
declare r record;
begin
  for r in select schemaname, tablename, policyname from pg_policies
           where schemaname = 'public' and tablename in ('profiles','role_permissions')
  loop
    execute format('drop policy %I on %I.%I', r.policyname, r.schemaname, r.tablename);
  end loop;
end $$;

drop policy if exists "own profile or admin" on public.profiles;
create policy "own profile or admin" on public.profiles
  for select to authenticated using (id = auth.uid() or public.is_admin());
drop policy if exists "admin updates profiles" on public.profiles;
create policy "admin updates profiles" on public.profiles
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "admin deletes profiles" on public.profiles;
create policy "admin deletes profiles" on public.profiles
  for delete to authenticated using (public.is_admin());

drop policy if exists "read permissions" on public.role_permissions;
create policy "read permissions" on public.role_permissions
  for select to authenticated using (true);
drop policy if exists "admin manages permissions" on public.role_permissions;
create policy "admin manages permissions" on public.role_permissions
  for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- Senos taisyklės „tik @eventsolutions.lt“ keičiamos taisyklėmis pagal lygį.
-- Visos ankstesnės šių lentelių taisyklės pašalinamos ir sukuriamos iš naujo.
do $$
declare r record;
begin
  for r in select schemaname, tablename, policyname from pg_policies
           where schemaname = 'public'
             and tablename in ('app_state','events','rentals','projects','project_items','vehicle_reminders')
  loop
    execute format('drop policy %I on %I.%I', r.policyname, r.schemaname, r.tablename);
  end loop;
end $$;

-- bendri duomenys: skaito visi patvirtinti, rašo tik turintys teisę į tą skiltį
alter table public.app_state enable row level security;
create policy "approved read app state" on public.app_state
  for select to authenticated using (public.is_approved());
create policy "insert app state by section" on public.app_state
  for insert to authenticated with check (public.app_state_can_edit(key));
create policy "update app state by section" on public.app_state
  for update to authenticated using (public.app_state_can_edit(key)) with check (public.app_state_can_edit(key));
create policy "delete app state admin" on public.app_state
  for delete to authenticated using (public.is_admin());

-- renginiai ir paėmimai (vienas kito sąrašuose rodomi, todėl skaito abu)
alter table public.events  enable row level security;
alter table public.rentals enable row level security;
create policy "view events" on public.events
  for select to authenticated using (public.can_view('events') or public.can_view('rentals'));
create policy "edit events" on public.events
  for all to authenticated using (public.can_edit('events')) with check (public.can_edit('events'));
create policy "view rentals" on public.rentals
  for select to authenticated using (public.can_view('rentals') or public.can_view('events'));
create policy "edit rentals" on public.rentals
  for all to authenticated using (public.can_edit('rentals')) with check (public.can_edit('rentals'));

-- projektai: kuria / trina „Projektai“, krovimo planą saugo ir „Krovimas“
alter table public.projects      enable row level security;
alter table public.project_items enable row level security;
create policy "view projects" on public.projects
  for select to authenticated using (public.can_view('projects') or public.can_view('load'));
create policy "create projects" on public.projects
  for insert to authenticated with check (public.can_edit('projects'));
create policy "update projects" on public.projects
  for update to authenticated using (public.can_edit('projects') or public.can_edit('load'))
  with check (public.can_edit('projects') or public.can_edit('load'));
create policy "delete projects" on public.projects
  for delete to authenticated using (public.can_edit('projects'));
create policy "view project items" on public.project_items
  for select to authenticated using (public.can_view('projects') or public.can_view('load'));
create policy "edit project items" on public.project_items
  for all to authenticated using (public.can_edit('projects') or public.can_edit('load'))
  with check (public.can_edit('projects') or public.can_edit('load'));
-- viešos nuorodos (?share=…) veikia ir be prisijungimo
create policy "public shared projects" on public.projects
  for select to anon using (share_enabled = true);
create policy "public shared project items" on public.project_items
  for select to anon using (exists (select 1 from public.projects p
                                     where p.id = project_id and p.share_enabled = true));

-- automobilių dokumentų priminimai
alter table public.vehicle_reminders enable row level security;
create policy "view reminders" on public.vehicle_reminders
  for select to authenticated using (public.can_view('fleet'));
create policy "edit reminders" on public.vehicle_reminders
  for all to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
