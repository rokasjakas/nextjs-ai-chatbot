-- ============================================================
-- Transportas: KASKO draudimo galiojimas (šalia draudimo, tech. apžiūros ir kelių mokesčio)
--  * vehicle_reminders.kasko_until – priminimai el. paštu kaip ir kitiems dokumentams (funkcija vehicle-reminders)
--  * KASKO nebūtinas: jei data neįrašyta, apie jį neprimenama
-- Reikia: vehicle_reminders.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.vehicle_reminders add column if not exists kasko_until date;
notify pgrst, 'reload schema';
