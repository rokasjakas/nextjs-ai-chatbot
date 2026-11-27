-- ============================================================
-- Signalizacija → Laikinas kodas: privalomas vardas, pavardė; el. paštas nebūtinas.
-- Tik jei alarm.sql jau buvo paleistas anksčiau (naujas alarm.sql tai jau turi).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.alarm_temp_codes add column if not exists person_name text;
alter table public.alarm_temp_codes alter column email drop not null;
alter table public.alarm_temp_codes drop constraint if exists alarm_temp_codes_email_check;
notify pgrst, 'reload schema';
