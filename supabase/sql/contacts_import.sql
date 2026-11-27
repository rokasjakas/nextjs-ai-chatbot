-- ============================================================
-- Kontaktų įkėlimas iš Excel (Žmonės → „Įkelti Excel“, lapai „NEW Freelance“, „Organizatorių kontaktai“,
-- „RENT kompanijos“):
--  * Prisijungimai / Kontaktai: nauja skiltis „RENT kompanijos“ (cred_entries.cat = 'rent')
--  * contacts_merge(keep, drop) – to paties žmogaus dublikatas sujungiamas: jo skambučiai, priminimai
--    ir įkainiai pereina į paliekamą kontaktą, dublikatas ištrinamas
-- Reikia: creds.sql, people.sql, people3.sql, contact_rates.sql. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.cred_entries drop constraint if exists cred_entries_cat_check;
alter table public.cred_entries add constraint cred_entries_cat_check check (cat in ('app','web','contact','email','rent'));

create or replace function public.contacts_merge(p_keep text, p_drop text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.can_edit('people') then raise exception 'Nėra teisės.'; end if;
  if p_keep is null or p_drop is null or p_keep = p_drop then return; end if;
  if not exists (select 1 from public.contacts where id = p_keep) then raise exception 'Kontaktas nerastas.'; end if;
  update public.contact_calls set contact_id = p_keep where contact_id = p_drop;
  begin update public.booking_reminders set contact_id = p_keep where contact_id = p_drop; exception when undefined_table then null; end;
  begin
    if exists (select 1 from public.contact_rates where contact_id = p_keep) then delete from public.contact_rates where contact_id = p_drop;
    else update public.contact_rates set contact_id = p_keep where contact_id = p_drop; end if;
  exception when undefined_table then null; end;
  delete from public.contacts where id = p_drop;
end $$;
revoke all on function public.contacts_merge(text, text) from public, anon;
grant execute on function public.contacts_merge(text, text) to authenticated;

notify pgrst, 'reload schema';
