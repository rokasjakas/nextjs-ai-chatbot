-- ============================================================
-- Transportas: tepalo keitimas, moto valandos ir profilaktika
--  * engine_hours – moto valandos (prie bet kurio įrašo, kaip ir rida)
--  * data (jsonb) – papildomi duomenys:
--      tepalo keitimas (kind 'service', kategorija „Tepalo keitimas“):
--        { oil:{ type, liters, next_km, next_hours, next_date } }
--      profilaktika (kind 'check'):
--        { fluids:{ washer:{v,u}, oil:{v,u}, antifreeze:{v,u} }, condition:'good'|'fair'|'bad' }
--  * kind 'check' – profilaktika: gali įrašyti kiekvienas, kas mato „Transportą“ (kaip ir problemą)
-- Reikia: vehicle_logs.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.vehicle_logs add column if not exists engine_hours numeric(10,1)
  check (engine_hours is null or (engine_hours >= 0 and engine_hours < 1000000));
alter table public.vehicle_logs add column if not exists data jsonb not null default '{}'::jsonb;

alter table public.vehicle_logs drop constraint if exists vehicle_logs_kind_check;
alter table public.vehicle_logs add constraint vehicle_logs_kind_check check (kind in ('service','problem','check'));

drop policy if exists "fleet logs add" on public.vehicle_logs;
create policy "fleet logs add" on public.vehicle_logs for insert to authenticated
  with check (public.can_view('fleet') and created_by = auth.uid() and (kind in ('problem','check') or public.can_edit('fleet')));
drop policy if exists "fleet logs change" on public.vehicle_logs;
create policy "fleet logs change" on public.vehicle_logs for update to authenticated
  using (public.can_edit('fleet') or created_by = auth.uid())
  with check (public.can_edit('fleet') or (created_by = auth.uid() and kind in ('problem','check')));

notify pgrst, 'reload schema';
