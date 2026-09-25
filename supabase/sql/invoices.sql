-- ============================================================
-- Admin+, Super Admin ir Sąskaitos
--  * profiles.level: 'plus' = Admin+ (admin + sąskaitų tvirtinimas),
--    'super' = Super Admin (mato viską, gali pats keisti savo lygį ir grįžti).
--    Duomenų bazėje jų role lieka 'admin', todėl visos admin teisės galioja.
--  * Admin+ lygį skirti / nuimti gali tik Admin+ ir Super Admin;
--    Super Admin lygio niekas kitas keisti negali.
--  * invoices — gautos sąskaitos (Freelance / Paslaugų / Nuomos): įkelia visi,
--    kas gali redaguoti skiltį „Sąskaitos“; mato savo įkeltas, Admin+ – visas.
--  * invoice-files — saugykla failams (kai R2 neprijungtas).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.profiles add column if not exists level text;
alter table public.profiles drop constraint if exists profiles_level_check;
alter table public.profiles add constraint profiles_level_check check (level is null or level in ('plus','super'));

create or replace function public.is_super() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select level = 'super' from public.profiles where id = auth.uid()), false)
$$;
create or replace function public.is_plus() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'admin' and level in ('plus','super') from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.is_super(), public.is_plus() to authenticated;

-- lygio ir papildomo lygio keitimo taisyklės
create or replace function public.profiles_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if old.role = 'admin' and new.role <> 'admin'
     and not exists (select 1 from public.profiles where role = 'admin' and id <> old.id) then
    raise exception 'Negalima pašalinti paskutinio administratoriaus.';
  end if;
  -- auth.uid() is null: Supabase SQL Editor or server functions (service role)
  if auth.uid() is not null and coalesce(current_setting('app.super_switch', true), '') <> '1' then
    if not public.is_admin() then
      if new.id is distinct from old.id or new.role is distinct from old.role or new.level is distinct from old.level
         or new.email is distinct from old.email or new.approved_at is distinct from old.approved_at
         or new.approved_by is distinct from old.approved_by or new.notified_at is distinct from old.notified_at then
        raise exception 'Šių profilio laukų keisti negalima.';
      end if;
    end if;
    -- Super Admin: only he himself (through super_set_role) may change him
    if old.level = 'super' and (new.role is distinct from old.role or new.level is distinct from old.level) then
      raise exception 'Super Admin lygio keisti negalima.';
    end if;
    if new.level = 'super' and old.level is distinct from 'super' then
      raise exception 'Super Admin lygio suteikti negalima.';
    end if;
    -- Admin+ is given and taken only by Admin+ / Super Admin
    if (new.level is distinct from old.level or (old.level = 'plus' and new.role is distinct from old.role)) and not public.is_plus() then
      raise exception 'Admin+ lygį skirti gali tik Admin+ arba Super Admin.';
    end if;
  end if;
  -- leaving the admin role takes Admin+ away (Super Admin keeps his mark)
  if new.role <> 'admin' and new.level = 'plus' then new.level := null; end if;
  if new.role <> old.role and old.role = 'pending' and new.role not in ('pending','blocked') then
    new.approved_at := now();
    new.approved_by := coalesce(auth.jwt() ->> 'email', new.approved_by);
  end if;
  return new;
end $$;

-- Super Admin changes his own level to try the app as another level, and back
create or replace function public.super_set_role(r text) returns text
  language plpgsql security definer set search_path = public as $$
begin
  if not public.is_super() then raise exception 'Tik Super Admin.'; end if;
  if r not in ('admin','pm','office','tech','freelance','runner') then raise exception 'Nežinomas lygis.'; end if;
  perform set_config('app.super_switch', '1', true);
  update public.profiles set role = r where id = auth.uid();
  return r;
end $$;
revoke all on function public.super_set_role(text) from public;
grant execute on function public.super_set_role(text) to authenticated;

-- the Super Admin
update public.profiles set role = 'admin', level = 'super' where lower(email) = 'rokas@eventsolutions.lt';

-- ---------- skiltis „Sąskaitos“ ----------
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people','newproj','invoices'));
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','invoices',true,true), ('office','invoices',true,true), ('tech','invoices',true,true),
  ('freelance','invoices',true,true), ('runner','invoices',false,false)
on conflict (role, section) do nothing;

create table if not exists public.invoices (
  id            uuid primary key default gen_random_uuid(),
  created_at    timestamptz not null default now(),
  created_by    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  kind          text not null check (kind in ('freelance','service','rent')),
  supplier      text,
  number        text,
  amount        numeric(12,2),
  invoice_date  date,
  due_date      date,
  note          text,
  files         jsonb not null default '[]'::jsonb,   -- [{path,name,type,size}]
  status        text not null default 'new' check (status in ('new','approved','rejected','later','sent','queued','paid')),
  decision_note text,
  decision_by   uuid references auth.users(id) on delete set null,
  decision_at   timestamptz,
  remind_at     timestamptz,
  reminded_at   timestamptz,
  sent          jsonb not null default '[]'::jsonb,   -- [{at, by, by_email, to:[], comment, token}]
  responses     jsonb not null default '[]'::jsonb,   -- [{at, who, kind:'paid'|'queued'|'reply', text}]
  uploader_seen boolean not null default true
);
create index if not exists invoices_created_by_idx on public.invoices (created_by);
create index if not exists invoices_status_idx on public.invoices (status);
alter table public.invoices enable row level security;

drop policy if exists "invoices add" on public.invoices;
create policy "invoices add" on public.invoices
  for insert to authenticated with check (
    created_by = auth.uid() and public.can_edit('invoices')
    and status = 'new' and decision_by is null and decision_at is null and sent = '[]'::jsonb and responses = '[]'::jsonb
  );
drop policy if exists "invoices read" on public.invoices;
create policy "invoices read" on public.invoices
  for select to authenticated using (created_by = auth.uid() or public.is_plus());
drop policy if exists "invoices decide" on public.invoices;
create policy "invoices decide" on public.invoices
  for update to authenticated using (public.is_plus()) with check (public.is_plus());
drop policy if exists "invoices delete" on public.invoices;
create policy "invoices delete" on public.invoices
  for delete to authenticated using (public.is_plus() or (created_by = auth.uid() and status = 'new'));
grant select, insert, update, delete on public.invoices to authenticated;

-- the uploader marks the answer as seen
create or replace function public.invoice_seen(ids uuid[]) returns void
  language sql security definer set search_path = public as $$
  update public.invoices set uploader_seen = true where id = any(ids) and created_by = auth.uid();
$$;
revoke all on function public.invoice_seen(uuid[]) from public;
grant execute on function public.invoice_seen(uuid[]) to authenticated;

do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'invoices') then
    execute 'alter publication supabase_realtime add table public.invoices';
  end if;
end $$;

-- files: <uploader id>/<invoice id>/<file>
insert into storage.buckets (id, name, public) values ('invoice-files', 'invoice-files', false) on conflict (id) do nothing;
drop policy if exists "invoice files view" on storage.objects;
create policy "invoice files view" on storage.objects
  for select to authenticated using (bucket_id = 'invoice-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_plus()));
drop policy if exists "invoice files add" on storage.objects;
create policy "invoice files add" on storage.objects
  for insert to authenticated with check (bucket_id = 'invoice-files' and (storage.foldername(name))[1] = auth.uid()::text and public.can_edit('invoices'));
drop policy if exists "invoice files delete" on storage.objects;
create policy "invoice files delete" on storage.objects
  for delete to authenticated using (bucket_id = 'invoice-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_plus()));

-- a Super Admin cannot be deleted by anyone else
create or replace function public.profiles_delete_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if old.role = 'admin' and not exists (select 1 from public.profiles where role = 'admin' and id <> old.id) then
    raise exception 'Negalima pašalinti paskutinio administratoriaus.';
  end if;
  if old.level = 'super' and auth.uid() is not null then
    raise exception 'Super Admin ištrinti negalima.';
  end if;
  return old;
end $$;
