-- ============================================================
-- „Išlaidos“: kuro pylimas iš sukaupto kompensacijų likučio
--  * comp_use – narys pažymi, kad prisipylė kuro iš sukaupto likučio
--               (litrais arba eurais); atimama iš jo likučio
-- Narys mato, prideda ir trina savo; Admin / Office / Projektų vadovas – visų.
-- Reikia: expenses.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.comp_use (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  used_on    date not null default current_date,
  unit       text not null default 'l' check (unit in ('eur','l')),
  liters     numeric(10,2),
  amount     numeric(12,2),
  note       text not null default '',
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now()
);
create index if not exists comp_use_user on public.comp_use (user_id, used_on);

alter table public.comp_use enable row level security;
drop policy if exists "comp use view" on public.comp_use;
create policy "comp use view" on public.comp_use for select to authenticated
  using (user_id = auth.uid() or public.buy_manager());
drop policy if exists "comp use add" on public.comp_use;
create policy "comp use add" on public.comp_use for insert to authenticated
  with check ((user_id = auth.uid() and public.is_approved()) or public.buy_manager());
drop policy if exists "comp use remove" on public.comp_use;
create policy "comp use remove" on public.comp_use for delete to authenticated
  using (user_id = auth.uid() or public.buy_manager());

revoke all on public.comp_use from anon;
grant select, insert, delete on public.comp_use to authenticated;
notify pgrst, 'reload schema';
