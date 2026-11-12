-- ============================================================
-- Transporto nuoma, 2 dalis (paleisti po rent_vehicles.sql)
--  * source 'auto' – įrašas sukurtas pačios programos iš renginių transporto
--    (valst. nr., kurio nėra įmonės parke, arba „Fura Alius“)
--  * dismissed – ištrintas automatinis įrašas: paslepiamas ir iš renginių
--    nebepridedamas
--  * tas pats valst. nr. – tik vieną kartą
--  * trečias tipas: būdos (kind 'box') šalia mikroautobusų ir fūrų
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.rent_vehicles add column if not exists source text not null default 'manual';
alter table public.rent_vehicles add column if not exists dismissed boolean not null default false;
alter table public.rent_vehicles drop constraint if exists rent_vehicles_kind_check;
alter table public.rent_vehicles add constraint rent_vehicles_kind_check check (kind in ('van','box','truck'));
create unique index if not exists rent_vehicles_plate on public.rent_vehicles (upper(regexp_replace(plate, '[^A-Za-z0-9]', '', 'g'))) where plate is not null and plate <> '';

-- Supabase: read the list of columns again
notify pgrst, 'reload schema';
