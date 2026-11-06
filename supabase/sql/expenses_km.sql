-- „Išlaidos“: kilometrai prie kuro išlaidos (jei expenses.sql jau paleistas anksčiau)
-- Supabase → SQL Editor → New query → įklijuok → Run. Saugu paleisti pakartotinai.
alter table public.expenses add column if not exists km numeric(10,1);
notify pgrst, 'reload schema';
