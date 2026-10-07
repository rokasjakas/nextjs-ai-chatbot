-- ============================================================
-- Bolt / Wolt teisės pagal lygius
--  * Admin           – mato viską: kelionių kainas, sumas, Wolt išlaidas
--  * Office          – įkelia Bolt dokumentus, mato kas ir kiek kelionių atliko, keičia „darbo / asmeninė“,
--                      bet KAINŲ NEGAUNA (stulpelis amount jam neperduodamas)
--  * Projektų vadovas, Tech – mato tik savo keliones (su savo kainomis)
--  * Freelance, Runner – Bolt nemato
--  Kainos gaunamos tik per bolt_trip_amounts(): Admin – visos, kiti – tik savo kelionių.
--  Wolt (išlaidos) – tik Admin.
-- Reikia: office_bolt.sql (ir office_bolt3.sql). Saugu paleisti pakartotinai.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- ============================================================

-- the trips: every column except the price can be read (the rows themselves follow the policies below)
revoke select on public.bolt_trips from authenticated;
grant select (id, report_id, trip_at, trip_on, person_name, phone, vehicle_cat, person_id, from_addr, to_addr, note, kind, kind_manual, checked_by, checked_name, checked_at)
  on public.bolt_trips to authenticated;
grant insert, update, delete on public.bolt_trips to authenticated;

drop policy if exists "bolt trips own" on public.bolt_trips;
create policy "bolt trips own" on public.bolt_trips for select to authenticated
  using (person_id = auth.uid() and coalesce(public.my_role() in ('admin','pm','office','tech'), false));

-- the prices: Admin all, the others only their own trips
create or replace function public.bolt_trip_amounts(p_ids uuid[]) returns table (id uuid, amount numeric)
  language sql stable security definer set search_path = public as $$
  select t.id, t.amount from public.bolt_trips t
   where t.id = any(p_ids)
     and (public.my_role() = 'admin' or (t.person_id = auth.uid() and public.my_role() in ('pm','office','tech')))
$$;
revoke all on function public.bolt_trip_amounts(uuid[]) from public, anon;
grant execute on function public.bolt_trip_amounts(uuid[]) to authenticated;

-- Wolt: only Admin
drop policy if exists "wolt reports all" on public.wolt_reports;
create policy "wolt reports all" on public.wolt_reports for all to authenticated
  using (public.is_admin()) with check (public.is_admin());
drop policy if exists "wolt orders all" on public.wolt_orders;
create policy "wolt orders all" on public.wolt_orders for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

notify pgrst, 'reload schema';
