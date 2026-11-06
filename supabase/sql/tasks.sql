-- ============================================================
-- Užduotys: savo užduotys ir užduotys kitiems nariams
--  * tasks — užduotis: kas sukūrė, kam paskirta (assignees; tuščia = sau),
--    atsakingas (lead), terminas (due_at), priminimai (remind),
--    kas jau atliko (done: {narys: laikas}), kurie priminimai išsiųsti (sent).
--  * task_set_done(id, done) — narys pažymi „atlikta“ (tik save).
--  * senos užduotys (todos) perkeliamos į naują lentelę.
--  * priminimus kas 5 min. siunčia funkcija push-notify (pranešimas telefone
--    ir el. laiškas) — ta pati užduotis kaip automobilių priminimų, tik kita
--    funkcija; slaptažodis paimamas iš jos, nieko įrašyti nereikia.
-- Paleisti PO calendar.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.tasks (
  id          uuid primary key default gen_random_uuid(),
  title       text not null check (char_length(title) between 1 and 300),
  note        text not null default '',
  due_at      timestamptz,
  created_by  uuid not null default auth.uid() references auth.users(id) on delete cascade,
  assignees   uuid[] not null default '{}',
  lead        uuid references auth.users(id) on delete set null,
  remind      jsonb not null default '{}'::jsonb,
  done        jsonb not null default '{}'::jsonb,
  sent        jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists tasks_created_by_idx on public.tasks (created_by);
create index if not exists tasks_assignees_idx on public.tasks using gin (assignees);
create index if not exists tasks_due_idx on public.tasks (due_at);

alter table public.tasks enable row level security;
drop policy if exists "see my tasks" on public.tasks;
create policy "see my tasks" on public.tasks
  for select to authenticated
  using (created_by = auth.uid() or auth.uid() = any(assignees) or lead = auth.uid());
drop policy if exists "create tasks" on public.tasks;
create policy "create tasks" on public.tasks
  for insert to authenticated with check (created_by = auth.uid() and public.is_approved());
drop policy if exists "edit own tasks" on public.tasks;
create policy "edit own tasks" on public.tasks
  for update to authenticated using (created_by = auth.uid()) with check (created_by = auth.uid());
drop policy if exists "delete own tasks" on public.tasks;
create policy "delete own tasks" on public.tasks
  for delete to authenticated using (created_by = auth.uid());

-- „atlikta“ gali pažymėti kiekvienas, kuriam užduotis paskirta (ar atsakingas), bet tik už save
create or replace function public.task_set_done(tid uuid, is_done boolean)
returns public.tasks
language plpgsql security definer set search_path = public as $$
declare t public.tasks;
begin
  select * into t from public.tasks where id = tid;
  if t.id is null then raise exception 'Užduotis nerasta'; end if;
  if not coalesce(t.created_by = auth.uid() or auth.uid() = any(t.assignees) or t.lead = auth.uid(), false) then
    raise exception 'Ši užduotis ne tau';
  end if;
  update public.tasks
     set done = case when is_done then done || jsonb_build_object(auth.uid()::text, now())
                     else done - auth.uid()::text end,
         updated_at = now()
   where id = tid
  returning * into t;
  return t;
end $$;
revoke all on function public.task_set_done(uuid, boolean) from public;
grant execute on function public.task_set_done(uuid, boolean) to authenticated;

-- senos užduotys (todos) → naujos (tas pats id, todėl dvigubai neperkeliama)
do $$
begin
  if exists (select 1 from information_schema.tables where table_schema = 'public' and table_name = 'todos') then
    insert into public.tasks (id, title, note, due_at, created_by, remind, created_at)
    select t.id, t.title, coalesce(t.description, ''),
           case when t.due_date is null then null
                else ((t.due_date + coalesce(t.due_time, time '09:00')) at time zone 'Europe/Vilnius') end,
           t.user_id,
           case when t.due_date is null then '{}'::jsonb else '{"before":[0],"push":true}'::jsonb end,
           t.created_at
      from public.todos t
    on conflict (id) do nothing;
  end if;
end $$;

-- sąrašai atsinaujina realiu laiku
alter table public.tasks replica identity full;
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'tasks') then
    execute 'alter publication supabase_realtime add table public.tasks';
  end if;
end $$;

-- priminimai kas 5 min.
do $$
declare cmd text;
begin
  if not exists (select 1 from pg_extension where extname = 'pg_cron') then
    raise notice 'pg_cron neįjungtas — pirma paleisk vehicle_reminders_cron.sql';
    return;
  end if;
  select command into cmd from cron.job where jobname = 'vehicle-reminders-daily';
  if cmd is null then
    raise notice 'Nerasta automobilių priminimų užduotis (vehicle-reminders-daily) — pirma paleisk vehicle_reminders_cron.sql';
    return;
  end if;
  cmd := replace(cmd, '/functions/v1/vehicle-reminders', '/functions/v1/push-notify');
  if exists (select 1 from cron.job where jobname = 'task-reminders') then
    perform cron.unschedule('task-reminders');
  end if;
  perform cron.schedule('task-reminders', '*/5 * * * *', cmd);
end $$;
