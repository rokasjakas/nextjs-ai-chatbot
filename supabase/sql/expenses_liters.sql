-- ============================================================
-- „Išlaidos“: kompensacija eurais ARBA litrais
--  * expenses.comp_unit   – 'eur' (kompensacija €) arba 'l' (kompensacija litrais kuro)
--  * uta_personal.unit    – asmeninis UTA pylimas atimamas iš sukauptų € ('eur') arba litrų ('l')
-- Reikia: expenses.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.expenses add column if not exists comp_unit text not null default 'eur';
alter table public.expenses drop constraint if exists expenses_comp_unit_check;
alter table public.expenses add constraint expenses_comp_unit_check check (comp_unit in ('eur','l'));
alter table public.uta_personal add column if not exists unit text not null default 'eur';
alter table public.uta_personal drop constraint if exists uta_personal_unit_check;
alter table public.uta_personal add constraint uta_personal_unit_check check (unit in ('eur','l'));
notify pgrst, 'reload schema';
