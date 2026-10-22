-- ============================================================
-- Bolt: kelionės automobilio kategorija (Vehicle category group iš Bolt Excel).
-- Tik jei office_bolt.sql jau buvo paleistas anksčiau. Saugu paleisti pakartotinai.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- ============================================================
alter table public.bolt_trips add column if not exists vehicle_cat text;
notify pgrst, 'reload schema';
