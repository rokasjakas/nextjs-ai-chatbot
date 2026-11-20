-- ============================================================
-- Žmonės 4: žyma „Gali“ — žmogus negali prašomomis dienomis,
-- bet pasiūlė kitas (gali dirbti tą dieną).
-- Paleisti PO people2.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.contact_calls drop constraint if exists contact_calls_outcome_check;
alter table public.contact_calls add constraint contact_calls_outcome_check
  check (outcome in ('calling','sutiko','atsisake','negali','placiau','neatsiliepe','gali'));
