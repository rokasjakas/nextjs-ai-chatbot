-- ============================================================
-- Transportas: „Registruoti įvykį“ (avarija, apgadinimas, bauda ir pan.)
--  * vehicle_logs.kind 'incident' – data, laikas (data.time), kas nutiko, aprašymas, komentaras (data.comment),
--    vieta (data.loc), nuotraukos ir video (files, saugykla 'fleet-files')
--  * įregistruoti gali kiekvienas, kas mato „Transportą“ (kaip problemą ar profilaktiką); taisyti – pats ir tie, kas redaguoja „Transportą“
-- Reikia: vehicle_logs.sql, vehicle_logs2.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.vehicle_logs drop constraint if exists vehicle_logs_kind_check;
alter table public.vehicle_logs add constraint vehicle_logs_kind_check check (kind in ('service','problem','check','incident'));

drop policy if exists "fleet logs add" on public.vehicle_logs;
create policy "fleet logs add" on public.vehicle_logs for insert to authenticated
  with check (public.can_view('fleet') and created_by = auth.uid() and (kind in ('problem','check','incident') or public.can_edit('fleet')));
drop policy if exists "fleet logs change" on public.vehicle_logs;
create policy "fleet logs change" on public.vehicle_logs for update to authenticated
  using (public.can_edit('fleet') or created_by = auth.uid())
  with check (public.can_edit('fleet') or (created_by = auth.uid() and kind in ('problem','check','incident')));

notify pgrst, 'reload schema';
