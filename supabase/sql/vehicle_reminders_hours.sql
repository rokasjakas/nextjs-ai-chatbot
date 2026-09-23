-- ============================================================
-- Priminimų valandos + tikrinimas kas valandą.
-- Paleisk Supabase → SQL Editor → įklijuok → Run (saugu paleisti pakartotinai).
-- ============================================================

-- Kuriomis valandomis (Lietuvos laiku, 0–23) siųsti priminimus.
alter table public.vehicle_reminders
  add column if not exists reminder_hours int[] not null default '{9}';

-- Kasdienis darbas dabar tikrina kas valandą (funkcija pati žiūri, ar ta valanda pasirinkta).
select cron.alter_job(
  (select jobid from cron.job where jobname = 'vehicle-reminders-daily'),
  schedule := '0 * * * *'
);
