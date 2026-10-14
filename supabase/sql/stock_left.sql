-- ============================================================
-- Sandėlis → „Likučiai“: einamieji daiktai (Tape, Skočas, Zateškės, Strečas, Baterijos…)
--  * stock_cats  – kategorijos (pridedamos pačių)
--  * stock_items – daiktai: kategorija, vienetai ('pcs' – vnt., 'pct' – %), kada laikyti „baigiasi“
--  * stock_counts – skaičiai iš darbų planų: darbų plano punktas „Likutis“ (item.stock = daikto id)
--    – pildant planą įrašytas skaičius automatiškai įrašomas čia (trigeris ant work_plan_runs)
-- Reikia: user_roles.sql (is_approved, can_edit), work_plans.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.stock_cats (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  sort       int not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.stock_items (
  id         uuid primary key default gen_random_uuid(),
  cat_id     uuid references public.stock_cats(id) on delete set null,
  name       text not null,
  unit       text not null default 'pcs' check (unit in ('pcs', 'pct')),
  min_level  numeric,                       -- mažiau – „baigiasi“
  note       text,
  sort       int not null default 0,
  active     boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.stock_counts (
  id        uuid primary key default gen_random_uuid(),
  item_id   uuid not null references public.stock_items(id) on delete cascade,
  value     numeric not null,
  run_id    uuid references public.work_plan_runs(id) on delete cascade,
  plan_id   uuid,
  plan_title text,
  user_id   uuid,
  user_name text,
  period    date,
  at        timestamptz not null default now(),
  unique (run_id, item_id)
);
create index if not exists stock_counts_item on public.stock_counts (item_id, at desc);

alter table public.stock_cats enable row level security;
alter table public.stock_items enable row level security;
alter table public.stock_counts enable row level security;
drop policy if exists "stock cats view" on public.stock_cats;
create policy "stock cats view" on public.stock_cats for select to authenticated using (public.is_approved());
drop policy if exists "stock cats edit" on public.stock_cats;
create policy "stock cats edit" on public.stock_cats for all to authenticated using (public.can_edit('inventory')) with check (public.can_edit('inventory'));
drop policy if exists "stock items view" on public.stock_items;
create policy "stock items view" on public.stock_items for select to authenticated using (public.is_approved());
drop policy if exists "stock items edit" on public.stock_items;
create policy "stock items edit" on public.stock_items for all to authenticated using (public.can_edit('inventory')) with check (public.can_edit('inventory'));
drop policy if exists "stock counts view" on public.stock_counts;
create policy "stock counts view" on public.stock_counts for select to authenticated using (public.is_approved());
-- skaičiai įrašomi tik per darbų planą (trigeris)
revoke all on public.stock_cats, public.stock_items, public.stock_counts from anon;
grant select, insert, update, delete on public.stock_cats, public.stock_items to authenticated;
grant select on public.stock_counts to authenticated;

-- darbų plano užpildymas → likučiai: kiekvienas punktas su „stock“, kurio atsakyme yra skaičius (n)
create or replace function public.stock_counts_from_run() returns trigger
  language plpgsql security definer set search_path = public as $$
declare it jsonb; a jsonb; sid uuid; v numeric; nm text;
begin
  select trim(coalesce(first_name, '') || ' ' || coalesce(last_name, '')) into nm from public.profiles where id = new.user_id;
  for it in select i from jsonb_array_elements(case when jsonb_typeof(new.snapshot -> 'groups') = 'array' then new.snapshot -> 'groups' else '[]'::jsonb end) g,
                         jsonb_array_elements(case when jsonb_typeof(g -> 'items') = 'array' then g -> 'items' else '[]'::jsonb end) i
            where coalesce(i ->> 'stock', '') ~ '^[0-9a-f-]{36}$' loop
    sid := (it ->> 'stock')::uuid;
    if not exists (select 1 from public.stock_items where id = sid) then continue; end if;
    a := new.answers -> (it ->> 'id');
    if a is null or jsonb_typeof(a -> 'n') <> 'number' then
      delete from public.stock_counts where run_id = new.id and item_id = sid;
      continue;
    end if;
    v := (a ->> 'n')::numeric;
    if v < 0 or v > 1000000 then continue; end if;
    insert into public.stock_counts (item_id, value, run_id, plan_id, plan_title, user_id, user_name, period, at)
    values (sid, v, new.id, new.plan_id, left(new.snapshot ->> 'title', 200), new.user_id, nullif(nm, ''), new.period, now())
    on conflict (run_id, item_id) do update
      set value = excluded.value, at = case when stock_counts.value is distinct from excluded.value then now() else stock_counts.at end;
  end loop;
  return new;
end $$;
drop trigger if exists stock_counts_from_run on public.work_plan_runs;
create trigger stock_counts_from_run after insert or update on public.work_plan_runs
  for each row execute function public.stock_counts_from_run();

notify pgrst, 'reload schema';
