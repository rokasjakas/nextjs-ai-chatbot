-- ============================================================
-- RFID (Chainway C72 ir kiti skaitytuvai „klaviatūros“ režimu): puslapis rfid.html
--  * rfid_tags – kuri RFID žyma (EPC) kuriam sandėlio daiktui priklauso (ir, jei reikia, vieneto nr.)
--    mato visi patvirtinti nariai; priskiria / keičia / trina tie, kas redaguoja „Įrangą“
--  * rfid_inventories – inventorizacijos skenavimas: kokios žymos rastos ir kada
--    pradeda tie, kas mato „Įrangą“; mato tie, kas mato „Įrangą“
-- Reikia: user_roles.sql (is_approved, can_view, can_edit).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.rfid_tags (
  epc             text primary key check (length(epc) between 4 and 128),
  item_id         text not null,
  item_name       text,
  unit            text not null default '',
  note            text not null default '',
  created_by      uuid default auth.uid(),
  created_by_name text,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);
create index if not exists rfid_tags_item on public.rfid_tags (item_id);

create table if not exists public.rfid_inventories (
  id              uuid primary key default gen_random_uuid(),
  title           text not null default '',
  tags            jsonb not null default '[]'::jsonb,       -- [{epc, at}]
  created_by      uuid default auth.uid(),
  created_by_name text,
  created_at      timestamptz not null default now(),
  finished_at     timestamptz
);
create index if not exists rfid_inventories_time on public.rfid_inventories (created_at desc);

-- who wrote it: set by the server
create or replace function public.rfid_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  new.epc := upper(regexp_replace(coalesce(new.epc, ''), '\s+', '', 'g'));
  if tg_op = 'INSERT' then
    new.created_by := auth.uid(); new.created_at := now();
    new.created_by_name := coalesce((select nullif(trim(concat_ws(' ', p.first_name, p.last_name)), '') from public.profiles p where p.id = auth.uid()), new.created_by_name);
  else
    new.created_by := old.created_by; new.created_at := old.created_at; new.created_by_name := old.created_by_name;
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists rfid_tags_stamp on public.rfid_tags;
create trigger rfid_tags_stamp before insert or update on public.rfid_tags for each row execute function public.rfid_stamp();

create or replace function public.rfid_inv_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.created_by := auth.uid(); new.created_at := now();
    new.created_by_name := coalesce((select nullif(trim(concat_ws(' ', p.first_name, p.last_name)), '') from public.profiles p where p.id = auth.uid()), new.created_by_name);
  else
    new.created_by := old.created_by; new.created_at := old.created_at; new.created_by_name := old.created_by_name;
  end if;
  return new;
end $$;
drop trigger if exists rfid_inventories_stamp on public.rfid_inventories;
create trigger rfid_inventories_stamp before insert or update on public.rfid_inventories for each row execute function public.rfid_inv_stamp();

alter table public.rfid_tags enable row level security;
drop policy if exists "rfid tags view" on public.rfid_tags;
create policy "rfid tags view" on public.rfid_tags for select to authenticated using (public.is_approved());
drop policy if exists "rfid tags edit" on public.rfid_tags;
create policy "rfid tags edit" on public.rfid_tags for all to authenticated
  using (public.can_edit('inventory')) with check (public.can_edit('inventory'));
revoke all on public.rfid_tags from anon;
grant select, insert, update, delete on public.rfid_tags to authenticated;

alter table public.rfid_inventories enable row level security;
drop policy if exists "rfid inv view" on public.rfid_inventories;
create policy "rfid inv view" on public.rfid_inventories for select to authenticated using (public.can_view('inventory'));
drop policy if exists "rfid inv add" on public.rfid_inventories;
create policy "rfid inv add" on public.rfid_inventories for insert to authenticated with check (public.can_view('inventory'));
drop policy if exists "rfid inv change" on public.rfid_inventories;
create policy "rfid inv change" on public.rfid_inventories for update to authenticated
  using (created_by = auth.uid() or public.can_edit('inventory')) with check (created_by = auth.uid() or public.can_edit('inventory'));
drop policy if exists "rfid inv remove" on public.rfid_inventories;
create policy "rfid inv remove" on public.rfid_inventories for delete to authenticated using (public.can_edit('inventory'));
revoke all on public.rfid_inventories from anon;
grant select, insert, update, delete on public.rfid_inventories to authenticated;

notify pgrst, 'reload schema';
