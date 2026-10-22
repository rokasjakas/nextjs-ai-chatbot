-- ============================================================
-- Balsavimas: ar jis įjungtas (Admin → Balsavimai → Įjungti / Išjungti)
--  * poll_enabled() – balsavimo, rezultatų ekrano ir valdymo puslapiai paklausia vieną kartą atsidarę;
--    kai išjungta, jie nebesiunčia jokių užklausų, kol balsavimas vėl nebus įjungtas
--    (sutaupo Supabase srautą ir žurnalus – ekranas gali likti atidarytas paromis)
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create or replace function public.poll_enabled() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select (data->>'pollOn')::boolean from public.app_state where key = 'uiSettings'), false)
$$;
revoke all on function public.poll_enabled() from public;
grant execute on function public.poll_enabled() to anon, authenticated;
