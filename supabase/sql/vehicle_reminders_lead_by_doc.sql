-- ============================================================
-- Atskiras „priminti likus X dienų“ kiekvienam dokumentui
-- (draudimas, tech. apžiūra, kelių mokestis).
-- Paleisk Supabase → SQL Editor → įklijuok → Run (saugu paleisti pakartotinai).
-- ============================================================
alter table public.vehicle_reminders
  add column if not exists lead_days_by_doc jsonb not null default '{}'::jsonb;
