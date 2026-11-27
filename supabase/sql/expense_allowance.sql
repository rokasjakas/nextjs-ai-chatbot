-- ============================================================
-- „Išlaidos“: mėnesinis kompensavimo limitas nariui
--  * expense_allowance – kiek € nariui pridedama kiekvieną mėnesį (nuo kurio mėnesio);
--                        nepanaudotas likutis pereina į kitą mėnesį
--  * expenses.from_allow – išlaida apmokama iš sukaupto likučio (varnelė pildant)
-- Narys mato savo limitą; Admin / Office / Projektų vadovas – visų; nustato Admin / Office.
-- Reikia: expenses.sql, office_bolt.sql (office_admin).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.expense_allowance (
  user_id     uuid primary key references auth.users(id) on delete cascade,
  monthly     numeric(12,2) not null check (monthly >= 0),
  start_month date not null default date_trunc('month', now())::date,
  set_by      uuid default auth.uid(),
  updated_at  timestamptz not null default now()
);
alter table public.expenses add column if not exists from_allow boolean not null default false;

alter table public.expense_allowance enable row level security;
drop policy if exists "allowance view" on public.expense_allowance;
create policy "allowance view" on public.expense_allowance for select to authenticated
  using (user_id = auth.uid() or public.buy_manager());
drop policy if exists "allowance set" on public.expense_allowance;
create policy "allowance set" on public.expense_allowance for all to authenticated
  using (public.office_admin()) with check (public.office_admin());

revoke all on public.expense_allowance from anon;
grant select, insert, update, delete on public.expense_allowance to authenticated;

notify pgrst, 'reload schema';
