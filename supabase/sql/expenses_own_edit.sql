-- ============================================================
-- „Išlaidos“: narys pats taiso ir trina savo išlaidas bet kada
--  * pataisyta išlaida vėl laukia patikros (status 'new'), kompensacija nuimama
--  * ištrinti savo išlaidą galima ir patvirtintą / atmestą
-- Reikia: expenses.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
drop policy if exists "expenses edit" on public.expenses;
create policy "expenses edit" on public.expenses for update to authenticated
  using (public.buy_manager() or user_id = auth.uid())
  with check (public.buy_manager() or (user_id = auth.uid() and status = 'new' and comp is null));
drop policy if exists "expenses remove" on public.expenses;
create policy "expenses remove" on public.expenses for delete to authenticated
  using (public.buy_manager() or user_id = auth.uid());
notify pgrst, 'reload schema';
