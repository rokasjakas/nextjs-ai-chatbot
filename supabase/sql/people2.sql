-- ============================================================
-- Žmonės 2: bookingo žymos
--  * nauja žyma „Atsisakė“ (atsisake)
--  * žymos datą (for_date) galima pakeisti – „Sutiko“ galioja iki tos dienos
--  * žymą keisti gali ją uždėjęs žmogus arba administratorius
-- Paleisti PO people.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.contact_calls drop constraint if exists contact_calls_outcome_check;
alter table public.contact_calls add constraint contact_calls_outcome_check
  check (outcome in ('calling','sutiko','atsisake','negali','placiau','neatsiliepe'));

drop policy if exists "update own calls" on public.contact_calls;
create policy "update own calls" on public.contact_calls
  for update to authenticated using ((called_by = auth.uid() or public.is_admin()) and public.can_edit('people'))
  with check (public.can_edit('people'));

-- who called and when is fixed once written; the outcome, the note and the day change
revoke update on public.contact_calls from authenticated;
grant update (outcome, note, for_date) on public.contact_calls to authenticated;
