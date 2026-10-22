-- ============================================================
-- Teisės lentelėms (Supabase Data API) – TIK atkuriant programą naujame Supabase projekte iš senesnės kopijos be teisių.
-- Nuo 2026-10-30 Supabase naujoms lentelėms pats nebeduoda teisių (anon / authenticated / service_role), todėl atkurtos
-- lentelės be šio failo programai būtų nepasiekiamos („permission denied“).
-- Duoda tas pačias teises, kurias Supabase anksčiau duodavo pats; kas ką mato, ir toliau saugo lentelių RLS taisyklės.
-- Po to dar kartą paleisk supabase/sql/atnaujinimas.sql – jame esantys „revoke“ vėl sugriežtina, kur reikia.
-- Dabartiniame projekte šio failo leisti NEREIKIA.
-- ============================================================
grant usage on schema public to anon, authenticated, service_role;
grant select, insert, update, delete on all tables in schema public to anon, authenticated, service_role;
grant usage, select on all sequences in schema public to anon, authenticated, service_role;
grant execute on all functions in schema public to anon, authenticated, service_role;
