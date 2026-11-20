-- ============================================================
-- Užduotys 2: „Runner“ ir „Freelance“ lygio nariai užduočių nekuria –
-- jie tik gauna užduotis iš kitų (ir pažymi jas atliktas).
-- Paleisti PO tasks.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

drop policy if exists "create tasks" on public.tasks;
create policy "create tasks" on public.tasks
  for insert to authenticated with check (
    created_by = auth.uid() and public.is_approved()
    and coalesce(public.my_role(), '') not in ('runner', 'freelance')
  );
