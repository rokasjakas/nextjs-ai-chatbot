-- ============================================================
-- Windows programos atnaujinimai: saugykla „desktop“ (vieša, tik skaityti)
--  * GitHub (.github/workflows/desktop.yml) pats sukuria EventSolutions-Setup.exe,
--    padalina į dalis po 24 MB ir įkelia čia kartu su EventSolutions-Setup.json
--  * programa ir svetainės mygtukas „Atsisiųsti Windows (.exe)“ ima iš čia
--    (svetainės _redirects nukreipia senus adresus)
--  * įkelti gali tik serveris (service_role), visi kiti – tik atsisiųsti
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

insert into storage.buckets (id, name, public, file_size_limit)
values ('desktop', 'desktop', true, 52428800)
on conflict (id) do update set public = true, file_size_limit = 52428800;
