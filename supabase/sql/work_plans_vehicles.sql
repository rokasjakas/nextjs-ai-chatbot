-- ============================================================
-- „Darbų planas“ su automobiliais
--  * work_plans.vehicles – pasirinkti automobiliai (Transporto automobilių id). Plane jų esant, narys
--    pildo teiginius kiekvienam automobiliui atskirai (atsakymai saugomi „<automobilio id>::<teiginio id>“),
--    pabaigoje spaudžia „Darbų planas atliktas“; ataskaita matoma Transporte prie automobilio („Savaitinė patikra“)
-- Reikia: work_plans.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.work_plans add column if not exists vehicles text[] not null default '{}';

notify pgrst, 'reload schema';
