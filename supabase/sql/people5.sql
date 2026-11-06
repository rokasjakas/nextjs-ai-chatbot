-- ============================================================
-- Žmonės 5: žyma „Perskambinti“ — žmogus paprašė perskambinti ir
-- pasitikslinti dėl dienos (rodoma Žmonės → Užimtumas).
-- Paleisti PO people4.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.contact_calls drop constraint if exists contact_calls_outcome_check;
alter table public.contact_calls add constraint contact_calls_outcome_check
  check (outcome in ('calling','sutiko','atsisake','negali','placiau','neatsiliepe','gali','perskambinti'));
