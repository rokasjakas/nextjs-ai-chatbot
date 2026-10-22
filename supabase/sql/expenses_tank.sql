-- ============================================================
-- „Išlaidos“: mokėjimo būdas „Iš savo kuro“ (paid = 'tank')
--  kuras iš savo automobilio bako – be kvito ir be sumos
-- Reikia: expenses.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.expenses drop constraint if exists expenses_paid_check;
alter table public.expenses add constraint expenses_paid_check check (paid in ('uta','own','tank'));
notify pgrst, 'reload schema';
