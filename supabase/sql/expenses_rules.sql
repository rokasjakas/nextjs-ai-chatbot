-- ============================================================
-- „Išlaidos“ ir UTA: taisyklės
--  * expense_allowance.unit – nario balansas asmeniniams pylimams: 'eur' arba 'l' (kas mėnesį pridedama,
--    nepanaudotas likutis pereina į kitą mėnesį); balansą priskiria Admin+ narys
--  * uta_personal.receipts / note – asmeninis UTA pylimas pagrindžiamas kvitu (nuotrauka) ir, jei reikia, komentaru
--  * exp_month_open(d) – termino nėra: narys pateikia / taiso bet kada
--  * išlaidą patvirtinti / atmesti ir kompensaciją (€ arba l) priskirti gali tik Admin+ narys
-- Reikia: expenses.sql, expense_allowance.sql, expenses_liters.sql, invoices.sql (is_plus).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.is_plus() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'admin' and level in ('plus','super') from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.is_plus() to authenticated;

-- the month of day d can still be filled in by the member: until the 10th of the next month (Vilnius time)
create or replace function public.exp_month_open(d date) returns boolean
  language sql stable as $$
  select d is not null   -- no deadline any more (expenses_no_deadline.sql)
$$;
grant execute on function public.exp_month_open(date) to authenticated;
create or replace function public.exp_tx_open(tx uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select public.exp_month_open((select tx_date from public.uta_tx where id = tx))
$$;
grant execute on function public.exp_tx_open(uuid) to authenticated;

-- the balance for personal fills: euros or litres
alter table public.expense_allowance add column if not exists unit text not null default 'eur';
alter table public.expense_allowance drop constraint if exists expense_allowance_unit_check;
alter table public.expense_allowance add constraint expense_allowance_unit_check check (unit in ('eur','l'));
drop policy if exists "allowance set" on public.expense_allowance;
create policy "allowance set" on public.expense_allowance for all to authenticated
  using (public.is_plus()) with check (public.is_plus());

-- a personal fill: its receipt and a note
alter table public.uta_personal add column if not exists receipts jsonb not null default '[]'::jsonb;
alter table public.uta_personal add column if not exists note text not null default '';
drop policy if exists "uta personal add" on public.uta_personal;
create policy "uta personal add" on public.uta_personal for insert to authenticated
  with check (public.is_plus() or (user_id = auth.uid() and public.uta_tx_mine(tx_id) and public.exp_tx_open(tx_id)));
drop policy if exists "uta personal edit" on public.uta_personal;
create policy "uta personal edit" on public.uta_personal for update to authenticated
  using (public.is_plus() or (user_id = auth.uid() and public.exp_tx_open(tx_id)))
  with check (public.is_plus() or (user_id = auth.uid() and public.exp_tx_open(tx_id)));
drop policy if exists "uta personal remove" on public.uta_personal;
create policy "uta personal remove" on public.uta_personal for delete to authenticated
  using (public.is_plus() or (user_id = auth.uid() and public.exp_tx_open(tx_id)));
grant update on public.uta_personal to authenticated;

-- the member's own expenses: only while the month is open
drop policy if exists "expenses add" on public.expenses;
create policy "expenses add" on public.expenses for insert to authenticated
  with check (user_id = auth.uid() and public.is_approved() and status = 'new' and comp is null and public.exp_month_open(spent_on));
drop policy if exists "expenses edit" on public.expenses;
create policy "expenses edit" on public.expenses for update to authenticated
  using (public.is_plus() or public.buy_manager() or (user_id = auth.uid() and public.exp_month_open(spent_on)))
  with check (public.is_plus() or public.buy_manager() or (user_id = auth.uid() and status = 'new' and comp is null and public.exp_month_open(spent_on)));
drop policy if exists "expenses remove" on public.expenses;
create policy "expenses remove" on public.expenses for delete to authenticated
  using (public.is_plus() or (user_id = auth.uid() and public.exp_month_open(spent_on)));

-- approving / rejecting and the compensation: only an Admin+ member
-- (a member correcting an own expense sends it back to „waits“ – that is allowed)
create or replace function public.expenses_review_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if public.is_plus() then return new; end if;
  if new.status is distinct from old.status or new.comp is distinct from old.comp or new.comp_unit is distinct from old.comp_unit
     or new.review_note is distinct from old.review_note then
    if new.user_id = auth.uid() and new.status = 'new' and new.comp is null then return new; end if;
    raise exception 'Patvirtinti išlaidas ir priskirti kompensaciją gali tik Admin+ narys.';
  end if;
  return new;
end $$;
drop trigger if exists expenses_review_guard on public.expenses;
create trigger expenses_review_guard before update on public.expenses for each row execute function public.expenses_review_guard();

notify pgrst, 'reload schema';
