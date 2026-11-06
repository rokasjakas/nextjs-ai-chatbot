-- ============================================================
-- Automobilio QR kodas niekada nesikeičia: kodo pašalinti / pakeisti nebegalima.
-- Tik jei vehicle_qr.sql jau buvo paleistas anksčiau (naujas vehicle_qr.sql tai jau turi).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
drop policy if exists "vehicle qr remove" on public.vehicle_qr;
revoke update, delete on public.vehicle_qr from authenticated;
notify pgrst, 'reload schema';
