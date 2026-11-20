-- ============================================================
-- „Darbų planas“: darbus (planus) kuria ne tik Admin – ir Tech, Office, Projektų vadovai, sau ir kitiems.
--  * Admin – kaip anksčiau: mato ir keičia visus planus ir užpildymus
--  * Tech / Office / PV – kuria planus; mato, keičia ir trina TIK savo sukurtus; mato jų užpildymus ir nuotraukas
--  * kiti (Freelance, Runner) – tik pildo jiems priskirtus darbus
-- Reikia: work_plans.sql. Paleidžiama per „SQL paleidimas“. Saugu paleisti pakartotinai.
-- ============================================================

-- who may make plans: Tech and above
create or replace function public.wp_creator() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role in ('admin','pm','office','tech') from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.wp_creator() to authenticated;

-- the plan / the filled-in run belongs to a plan I made (security definer: read past the policies, no recursion)
create or replace function public.wp_plan_mine(p uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.work_plans w where w.id = p and w.created_by = auth.uid())
$$;
grant execute on function public.wp_plan_mine(uuid) to authenticated;
create or replace function public.wp_run_mine(r text) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.work_plan_runs x join public.work_plans w on w.id = x.plan_id
                 where x.id::text = r and w.created_by = auth.uid())
$$;
grant execute on function public.wp_run_mine(text) to authenticated;

-- plans (created_by is always the one who made it – trigger work_plans_touch)
drop policy if exists "wp view" on public.work_plans;
create policy "wp view" on public.work_plans for select to authenticated
  using (public.wp_admin() or created_by = auth.uid() or (public.is_approved() and auth.uid() = any(assignees)));
drop policy if exists "wp edit" on public.work_plans;
drop policy if exists "wp add" on public.work_plans;
create policy "wp add" on public.work_plans for insert to authenticated
  with check (public.wp_admin() or public.wp_creator());
drop policy if exists "wp change" on public.work_plans;
create policy "wp change" on public.work_plans for update to authenticated
  using (public.wp_admin() or (public.wp_creator() and created_by = auth.uid()))
  with check (public.wp_admin() or (public.wp_creator() and created_by = auth.uid()));
drop policy if exists "wp remove" on public.work_plans;
create policy "wp remove" on public.work_plans for delete to authenticated
  using (public.wp_admin() or (public.wp_creator() and created_by = auth.uid()));

-- the filled-in runs of my plans (seen, not changed – returning / removing stays Admin's)
drop policy if exists "wpr view" on public.work_plan_runs;
create policy "wpr view" on public.work_plan_runs for select to authenticated
  using (user_id = auth.uid() or public.wp_admin() or public.wp_plan_mine(plan_id));

-- their photos: <member>/<run id>/<file>
drop policy if exists "work files view" on storage.objects;
create policy "work files view" on storage.objects for select to authenticated
  using (bucket_id = 'work-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.wp_admin()
         or public.wp_run_mine((storage.foldername(name))[2])));

notify pgrst, 'reload schema';

select 'policy' as k, tablename || ' · ' || policyname || ' · ' || cmd as v from pg_policies
  where (schemaname = 'public' and tablename in ('work_plans', 'work_plan_runs')) or policyname like 'work files%'
  order by 1, 2;
