-- ============================================================
-- UŽDUOTYS: du lygiai – greitas To-Do ir išplėstinė (projekto tipo) užduotis
--  * tasks.kind      – 'todo' (greita) arba 'project' (išplėstinė)
--  * tasks.status    – nauja / vykdoma / laukiama / atlikta (atlikta ⇄ done žymos sutampa – trigeris)
--  * tasks.priority  – low / normal / high / urgent
--  * tasks.parent_id – subužduotis (ištrynus pagrindinę – ištrinamos ir jos)
--  * tasks.checklist – darbų sąrašas [{ id, t, ok, by, at }]
--  * tasks.event_id  – susieta su renginiu (events.id)
--  * tasks.shared    – bendrame sąraše: mato visi komandos nariai (ne runner / freelance)
--  * tasks.started_at / done_at – kada pradėta ir atlikta (ataskaitoms: trukmė, laiku ar vėluojant)
--  * task_log        – komentarai, failai ir veiksmų istorija (būsena, atsakingi, terminas, prioritetas)
--  * saugykla 'task-files' – prisegti failai, kelias <užduoties id>/<failas>
-- Reikia: tasks.sql, tasks2.sql, channel_tasks.sql. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.tasks add column if not exists kind text not null default 'todo';
alter table public.tasks add column if not exists status text not null default 'nauja';
alter table public.tasks add column if not exists priority text not null default 'normal';
alter table public.tasks add column if not exists parent_id uuid references public.tasks(id) on delete cascade;
alter table public.tasks add column if not exists checklist jsonb not null default '[]'::jsonb;
alter table public.tasks add column if not exists event_id text;
alter table public.tasks add column if not exists shared boolean not null default false;
alter table public.tasks add column if not exists started_at timestamptz;
alter table public.tasks add column if not exists done_at timestamptz;

do $$ begin
  alter table public.tasks add constraint tasks_kind_chk check (kind in ('todo','project'));
exception when duplicate_object then null; end $$;
do $$ begin
  alter table public.tasks add constraint tasks_status_chk check (status in ('nauja','vykdoma','laukiama','atlikta'));
exception when duplicate_object then null; end $$;
do $$ begin
  alter table public.tasks add constraint tasks_priority_chk check (priority in ('low','normal','high','urgent'));
exception when duplicate_object then null; end $$;

create index if not exists tasks_parent_idx on public.tasks (parent_id);
create index if not exists tasks_event_idx on public.tasks (event_id);
create index if not exists tasks_shared_idx on public.tasks (shared) where shared;

-- the tasks done before (everyone marked it) count as „atlikta“
update public.tasks t set status = 'atlikta', done_at = coalesce(t.done_at, t.updated_at)
 where t.status <> 'atlikta' and t.done <> '{}'::jsonb
   and not exists (select 1 from unnest(case when cardinality(t.assignees) > 0 then t.assignees else array[t.created_by] end) u
                   where not (t.done ? u::text));

-- a team member (not a runner / freelancer)
create or replace function public.is_staff() returns boolean
  language sql stable security definer set search_path = public as $$
  select public.is_approved() and coalesce(public.my_role(), '') not in ('runner', 'freelance')
$$;
grant execute on function public.is_staff() to authenticated;

-- who sees a task: its author, the people on it, the lead, a channel's members, and everyone on the team for a shared one
create or replace function public.task_visible(tid uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.tasks t where t.id = tid and (
    t.created_by = auth.uid() or auth.uid() = any(t.assignees) or t.lead = auth.uid()
    or (t.shared and public.is_staff())
    or (t.conversation_id is not null and public.is_conv_member(t.conversation_id))))
$$;
grant execute on function public.task_visible(uuid) to authenticated;

drop policy if exists "see my tasks" on public.tasks;
create policy "see my tasks" on public.tasks
  for select to authenticated
  using (created_by = auth.uid() or auth.uid() = any(assignees) or lead = auth.uid()
         or (shared and public.is_staff())
         or (conversation_id is not null and public.is_conv_member(conversation_id)));

-- the people on a task work on it together: status, checklist, comments; a shared one – anyone on the team
drop policy if exists "edit own tasks" on public.tasks;
create policy "edit own tasks" on public.tasks
  for update to authenticated
  using (created_by = auth.uid() or lead = auth.uid() or auth.uid() = any(assignees) or (shared and public.is_staff()))
  with check (created_by = auth.uid() or lead = auth.uid() or auth.uid() = any(assignees) or (shared and public.is_staff()) or public.is_staff());

drop policy if exists "delete own tasks" on public.tasks;
create policy "delete own tasks" on public.tasks
  for delete to authenticated using (created_by = auth.uid() or lead = auth.uid());

-- status ⇄ done marks; when it was started / done
create or replace function public.tasks_status_sync() returns trigger
  language plpgsql set search_path = public as $$
declare ppl uuid[]; all_done boolean; u uuid;
begin
  ppl := case when cardinality(new.assignees) > 0 then new.assignees else array[new.created_by] end;
  if tg_op = 'UPDATE' and new.status is distinct from old.status then
    if new.status = 'atlikta' then
      foreach u in array ppl loop
        if not (coalesce(new.done, '{}'::jsonb) ? u::text) then new.done := coalesce(new.done, '{}'::jsonb) || jsonb_build_object(u::text, now()); end if;
      end loop;
    elsif old.status = 'atlikta' then
      new.done := '{}'::jsonb;
    end if;
  elsif tg_op = 'UPDATE' and new.done is distinct from old.done then
    select bool_and(coalesce(new.done, '{}'::jsonb) ? x::text) into all_done from unnest(ppl) x;
    if coalesce(all_done, false) and new.status <> 'atlikta' then new.status := 'atlikta';
    elsif not coalesce(all_done, false) and new.status = 'atlikta' then new.status := case when new.started_at is null then 'nauja' else 'vykdoma' end;
    end if;
  end if;
  if new.status = 'vykdoma' and new.started_at is null then new.started_at := now(); end if;
  if new.status = 'atlikta' then new.done_at := coalesce(case when tg_op = 'UPDATE' and old.status = 'atlikta' then old.done_at end, now());
  else new.done_at := null; end if;
  return new;
end $$;
drop trigger if exists tasks_status_sync on public.tasks;
create trigger tasks_status_sync before insert or update on public.tasks
  for each row execute function public.tasks_status_sync();

-- comments, files and the history of a task
create table if not exists public.task_log (
  id       uuid primary key default gen_random_uuid(),
  task_id  uuid not null references public.tasks(id) on delete cascade,
  kind     text not null default 'comment',          -- comment / file / create / status / assign / due / priority / title / sub
  body     text not null default '' check (char_length(body) <= 4000),
  data     jsonb not null default '{}'::jsonb,
  by       uuid default auth.uid() references auth.users(id) on delete set null,
  at       timestamptz not null default now()
);
create index if not exists task_log_task_idx on public.task_log (task_id, at);
alter table public.task_log enable row level security;
drop policy if exists "task log read" on public.task_log;
create policy "task log read" on public.task_log for select to authenticated using (public.task_visible(task_id));
drop policy if exists "task log add" on public.task_log;
create policy "task log add" on public.task_log for insert to authenticated
  with check (by = auth.uid() and kind in ('comment', 'file') and public.task_visible(task_id));
drop policy if exists "task log delete" on public.task_log;
create policy "task log delete" on public.task_log for delete to authenticated using (by = auth.uid() and kind in ('comment', 'file'));

-- the history is written by the database itself (cannot be forgotten or faked)
create or replace function public.tasks_log_changes() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    insert into public.task_log (task_id, kind, body, by) values (new.id, 'create', new.title, auth.uid());
    if new.parent_id is not null then insert into public.task_log (task_id, kind, body, data, by) values (new.parent_id, 'sub', new.title, jsonb_build_object('id', new.id), auth.uid()); end if;
    return new;
  end if;
  if new.status is distinct from old.status then insert into public.task_log (task_id, kind, data, by) values (new.id, 'status', jsonb_build_object('from', old.status, 'to', new.status), auth.uid()); end if;
  if new.assignees is distinct from old.assignees or new.lead is distinct from old.lead then
    insert into public.task_log (task_id, kind, data, by) values (new.id, 'assign', jsonb_build_object('from', to_jsonb(old.assignees), 'to', to_jsonb(new.assignees), 'lead', new.lead), auth.uid()); end if;
  if new.due_at is distinct from old.due_at then insert into public.task_log (task_id, kind, data, by) values (new.id, 'due', jsonb_build_object('from', old.due_at, 'to', new.due_at), auth.uid()); end if;
  if new.priority is distinct from old.priority then insert into public.task_log (task_id, kind, data, by) values (new.id, 'priority', jsonb_build_object('from', old.priority, 'to', new.priority), auth.uid()); end if;
  if new.title is distinct from old.title then insert into public.task_log (task_id, kind, body, by) values (new.id, 'title', new.title, auth.uid()); end if;
  return new;
end $$;
drop trigger if exists tasks_log_changes on public.tasks;
create trigger tasks_log_changes after insert or update on public.tasks
  for each row execute function public.tasks_log_changes();

alter table public.task_log replica identity full;
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'task_log') then
    execute 'alter publication supabase_realtime add table public.task_log';
  end if;
end $$;

-- files of a task: task-files/<task id>/<file>, for whoever sees the task
insert into storage.buckets (id, name, public) values ('task-files', 'task-files', false) on conflict (id) do nothing;
create or replace function public.task_file_access(obj_name text) returns boolean
  language sql stable security definer set search_path = public as $$
  select case when (storage.foldername(obj_name))[1] ~ '^[0-9a-f-]{36}$'
              then public.task_visible(((storage.foldername(obj_name))[1])::uuid) else false end
$$;
grant execute on function public.task_file_access(text) to authenticated;
drop policy if exists "task files read" on storage.objects;
create policy "task files read" on storage.objects for select to authenticated using (bucket_id = 'task-files' and public.task_file_access(name));
drop policy if exists "task files add" on storage.objects;
create policy "task files add" on storage.objects for insert to authenticated with check (bucket_id = 'task-files' and public.task_file_access(name));
drop policy if exists "task files delete" on storage.objects;
create policy "task files delete" on storage.objects for delete to authenticated using (bucket_id = 'task-files' and public.task_file_access(name));

notify pgrst, 'reload schema';
