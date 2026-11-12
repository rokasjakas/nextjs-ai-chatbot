-- ============================================================
-- Freelancerių sąskaitos (2): laiškai freelanceriui
--  * nepatvirtinta → laiškas su priežastimi ir mygtuku „Taisyti sąskaitą“
--  * patvirtinta → „patvirtinta, perduota buhalterijai“; apmokėta → „apmokėta“
--  * ext_mailed – kas jau pranešta (tas pats laiškas antrą kartą nesiunčiamas)
-- Reikia: freelance_portal.sql. Funkcijos: freelance-portal, push-notify (naujos versijos).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.invoices add column if not exists ext_mailed text;
create index if not exists invoices_ext_email_idx on public.invoices (ext_email) where source = 'portal';

notify pgrst, 'reload schema';
