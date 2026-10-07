-- Sąskaitos: nauja rūšis „Pirkinių“. Supabase → SQL Editor → Run.
alter table public.invoices drop constraint if exists invoices_kind_check;
alter table public.invoices add constraint invoices_kind_check check (kind in ('freelance','service','rent','purchase'));
