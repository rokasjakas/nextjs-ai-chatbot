-- ============================================================
-- „Pirkiniai“: pirkinių skiltys (kaip Excel lapai: VIDEO, LIGHT, AUDIO, Bendri daiktai…)
--  * viena eilutė = viena skiltis; jos lentelė (eilutės, langeliai, formulės) – rows (jsonb)
--  * vieša (visible = 'public') – mato visi, kam leista „Pirkiniai“, keisti gali kas juos redaguoja;
--    tik man (visible = 'private') – mato ir keičia tik sukūręs
--  * viešumą ir pavadinimą keičia tik savininkas (ar administratorius)
--  * „Pasiūlymai“ (purchase_proposals): kiekvienas narys pasiūlo, ką pirkti – mato visi;
--    sąrašus (purchase_lists) mato ir tvarko tik Admin, Office ir Projektų vadovai – jie
--    pasiūlymą priima (įkelia į sąrašą) arba atmeta
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- skiltis „Pirkiniai“ teisių lentelėje ----------
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people','newproj','invoices','buy'));
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','buy',true,true), ('office','buy',true,true), ('tech','buy',true,true),
  ('freelance','buy',false,false), ('runner','buy',false,false)
on conflict (role, section) do nothing;

create table if not exists public.purchase_lists (
  id               uuid primary key default gen_random_uuid(),
  name             text not null default 'Nauja skiltis',
  visible          text not null default 'public' check (visible in ('public','private')),
  owner            uuid not null default auth.uid() references auth.users(id) on delete cascade,
  owner_name       text,
  sort             integer not null default 0,
  cols             jsonb not null default '[]'::jsonb,   -- column titles (A…H)
  rows             jsonb not null default '[]'::jsonb,   -- [{id, sec?, c:{A:'…', B:'=…'}}]
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  updated_by       uuid,
  updated_by_name  text
);
create index if not exists purchase_lists_sort on public.purchase_lists (sort, created_at);

create or replace function public.purchase_lists_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'UPDATE' and old.owner <> auth.uid() and not public.is_admin() then
    if new.owner <> old.owner or new.visible <> old.visible or new.name <> old.name then
      raise exception 'Pavadinimą ir matomumą keičia tik skilties savininkas.';
    end if;
  end if;
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end $$;
drop trigger if exists purchase_lists_guard on public.purchase_lists;
create trigger purchase_lists_guard before insert or update on public.purchase_lists
  for each row execute function public.purchase_lists_guard();

-- who keeps the lists: Admin, Office, Projektų vadovai
create or replace function public.buy_manager() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','office','pm'), false)
$$;
grant execute on function public.buy_manager() to authenticated;

alter table public.purchase_lists enable row level security;
drop policy if exists "purchase lists view" on public.purchase_lists;
create policy "purchase lists view" on public.purchase_lists for select to authenticated
  using (owner = auth.uid() or (visible = 'public' and public.buy_manager()));
drop policy if exists "purchase lists add" on public.purchase_lists;
create policy "purchase lists add" on public.purchase_lists for insert to authenticated
  with check (owner = auth.uid() and public.buy_manager());
drop policy if exists "purchase lists change" on public.purchase_lists;
create policy "purchase lists change" on public.purchase_lists for update to authenticated
  using (owner = auth.uid() or (visible = 'public' and public.buy_manager()))
  with check (owner = auth.uid() or (visible = 'public' and public.buy_manager()));
drop policy if exists "purchase lists delete" on public.purchase_lists;
create policy "purchase lists delete" on public.purchase_lists for delete to authenticated
  using (owner = auth.uid() or public.is_admin());
revoke all on public.purchase_lists from anon;
grant select, insert, update, delete on public.purchase_lists to authenticated;

-- ---------- Pasiūlymai ----------
create table if not exists public.purchase_proposals (
  id               uuid primary key default gen_random_uuid(),
  name             text not null,
  qty              numeric,
  price            numeric,
  link             text,
  category         text,
  prio             integer not null default 2,
  note             text,
  status           text not null default 'new' check (status in ('new','accepted','rejected')),
  list_id          uuid references public.purchase_lists(id) on delete set null,
  list_name        text,
  decision_note    text,
  decided_by_name  text,
  decided_at       timestamptz,
  created_by       uuid not null default auth.uid() references auth.users(id) on delete cascade,
  created_by_name  text,
  created_at       timestamptz not null default now()
);
create index if not exists purchase_proposals_time on public.purchase_proposals (created_at desc);
alter table public.purchase_proposals enable row level security;
drop policy if exists "proposals view" on public.purchase_proposals;
create policy "proposals view" on public.purchase_proposals for select to authenticated using (public.is_approved());
drop policy if exists "proposals add" on public.purchase_proposals;
create policy "proposals add" on public.purchase_proposals for insert to authenticated
  with check (public.is_approved() and created_by = auth.uid() and status = 'new');
drop policy if exists "proposals change" on public.purchase_proposals;
create policy "proposals change" on public.purchase_proposals for update to authenticated
  using (public.buy_manager() or (created_by = auth.uid() and status = 'new'))
  with check (public.buy_manager() or (created_by = auth.uid() and status = 'new'));
drop policy if exists "proposals delete" on public.purchase_proposals;
create policy "proposals delete" on public.purchase_proposals for delete to authenticated
  using (public.is_admin() or (created_by = auth.uid() and status = 'new'));
revoke all on public.purchase_proposals from anon;
grant select, insert, update, delete on public.purchase_proposals to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';
