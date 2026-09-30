-- ============================================================
-- Kanalo užduotys (chate → kanalas → „Užduotys“)
--  * užduotis gali priklausyti kanalui (tasks.conversation_id)
--  * kanalo užduotis mato visi kanalo nariai; atsakingas (kam paskirta)
--    pažymi „atlikta“ – užduotis pažaliuoja, neatlikta – raudona
--  * paskirta užduotis atsiranda ir atsakingo „Man paskirtos“ sąraše,
--    priminimai veikia kaip kitoms užduotims
-- Paleisti PO tasks.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

alter table public.tasks add column if not exists conversation_id uuid references public.conversations(id) on delete cascade;
create index if not exists tasks_conversation_idx on public.tasks (conversation_id);

-- mato: savo / paskirtas / kur atsakingas, ir visas savo kanalų užduotis
drop policy if exists "see my tasks" on public.tasks;
create policy "see my tasks" on public.tasks
  for select to authenticated
  using (created_by = auth.uid() or auth.uid() = any(assignees) or lead = auth.uid()
         or (conversation_id is not null and public.is_conv_member(conversation_id)));

-- kurti kanale gali tik to kanalo narys
drop policy if exists "create tasks" on public.tasks;
create policy "create tasks" on public.tasks
  for insert to authenticated
  with check (created_by = auth.uid() and public.is_approved()
              and (conversation_id is null or public.is_conv_member(conversation_id)));

-- Supabase: read the list of columns again
notify pgrst, 'reload schema';
