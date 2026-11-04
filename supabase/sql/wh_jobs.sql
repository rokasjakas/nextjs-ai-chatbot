-- ============================================================
-- Sandėlis → Sandėlio darbai (programėlės skiltis „whjobs“)
--   kind = 'job'  – sandėlio darbas: status open (nepradėta) / doing (vykdoma) / done (pabaigta)
--   kind = 'idea' – darbų pasiūlymas: status pending / rejected; patvirtinus (Admin) jis tampa darbu (kind 'job', status 'open')
-- Kurti ir keisti gali Tech ir aukštesni lygiai (Tech, Office, Projektų vadovas, Admin);
-- priskirti žmonės mato savo darbus ir gali pažymėti „atlikta“.
-- Priskirtas darbas tampa užduotimi (public.tasks) – todėl jis matomas priskirtųjų kalendoriuje ir užduotyse,
-- su priminimu termino dieną. Failai – saugykloje equipment-photos, aplanke whjobs/<darbo id>/.
-- Klausimai (questions): kam skirtas – pasirenkamas bet kuris narys (to_id); jis mato tą darbą ir atsako.
-- Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.wh_can() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.is_approved() and public.my_role() in ('admin', 'pm', 'office', 'tech'), false)
$$;
create or replace function public.wh_admin() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() = 'admin', false) or coalesce(public.is_super(), false)
$$;
-- a member someone asked a question in that job (they may see it and answer)
create or replace function public.wh_asked(qs jsonb) returns boolean
  language sql stable as $$
  select exists (select 1 from jsonb_array_elements(case when jsonb_typeof(qs) = 'array' then qs else '[]'::jsonb end) x where x->>'to_id' = auth.uid()::text or coalesce(x->'to_ids', '[]'::jsonb) ? auth.uid()::text)
$$;
revoke all on function public.wh_can(), public.wh_admin() from public, anon;
grant execute on function public.wh_can(), public.wh_admin() to authenticated;

create table if not exists public.wh_jobs (
  id               uuid primary key default gen_random_uuid(),
  kind             text not null default 'job' check (kind in ('job', 'idea')),
  status           text not null default 'open' check (status in ('open', 'doing', 'done', 'pending', 'rejected')),
  title            text not null check (char_length(title) between 1 and 300),
  note             text not null default '',
  priority         smallint not null default 2 check (priority between 1 and 3),   -- 1 aukštas, 2 vidutinis, 3 žemas
  due_date         date,
  assignees        uuid[] not null default '{}',
  files            jsonb not null default '[]'::jsonb,
  comments         jsonb not null default '[]'::jsonb,
  questions        jsonb not null default '[]'::jsonb,   -- [{ id, t, by, by_id, at, a, a_by, a_by_id, a_at }] – klausimai sukūrusiam ir atsakymai
  created_by       uuid not null default auth.uid() references auth.users(id) on delete cascade,
  created_by_name  text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  approved_by_name text,
  approved_at      timestamptz,
  decided_note     text not null default '',
  done_by_name     text,
  done_at          timestamptz,
  task_id          uuid
);
alter table public.wh_jobs add column if not exists questions jsonb not null default '[]'::jsonb;
alter table public.wh_jobs drop constraint if exists wh_jobs_status_check;
alter table public.wh_jobs add constraint wh_jobs_status_check check (status in ('open', 'doing', 'done', 'pending', 'rejected'));
create index if not exists wh_jobs_kind_status on public.wh_jobs (kind, status);
create index if not exists wh_jobs_assignees on public.wh_jobs using gin (assignees);

alter table public.wh_jobs enable row level security;
drop policy if exists "wh jobs view" on public.wh_jobs;
create policy "wh jobs view" on public.wh_jobs for select to authenticated
  using (public.wh_can() or auth.uid() = any(assignees) or public.wh_asked(questions));
drop policy if exists "wh jobs add" on public.wh_jobs;
create policy "wh jobs add" on public.wh_jobs for insert to authenticated
  with check (public.wh_can() and created_by = auth.uid());
drop policy if exists "wh jobs change" on public.wh_jobs;
create policy "wh jobs change" on public.wh_jobs for update to authenticated
  using (public.wh_can() or auth.uid() = any(assignees) or public.wh_asked(questions))
  with check (public.wh_can() or auth.uid() = any(assignees) or public.wh_asked(questions));
drop policy if exists "wh jobs delete" on public.wh_jobs;
create policy "wh jobs delete" on public.wh_jobs for delete to authenticated
  using (created_by = auth.uid() or public.wh_admin());
revoke all on public.wh_jobs from anon;
grant select, insert, update, delete on public.wh_jobs to authenticated;

-- rules the policies cannot say: a new one starts right; only Admin decides a proposal;
-- someone only assigned (not Tech and up) may only mark it done / not done and add comments
create or replace function public.wh_jobs_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    if new.kind = 'idea' then new.status := 'pending'; new.approved_at := null; new.approved_by_name := null;
    elsif new.status not in ('open', 'doing', 'done') then new.status := 'open'; end if;
  else
    if not public.wh_can() then
      if new.kind is distinct from old.kind or new.title is distinct from old.title or new.note is distinct from old.note
         or new.priority is distinct from old.priority or new.due_date is distinct from old.due_date
         or new.assignees is distinct from old.assignees or new.files is distinct from old.files
         or new.created_by is distinct from old.created_by then
        raise exception 'Gali tik pažymėti, kad atlikta, ir komentuoti';
      end if;
      -- only asked a question (not assigned): may only answer
      if not (auth.uid() = any(old.assignees)) and (new.status is distinct from old.status or new.comments is distinct from old.comments
         or new.done_at is distinct from old.done_at or new.done_by_name is distinct from old.done_by_name) then
        raise exception 'Gali tik atsakyti į klausimą';
      end if;
    end if;
    if old.kind = 'idea' and (new.kind is distinct from old.kind or new.status is distinct from old.status) and not public.wh_admin() then
      raise exception 'Pasiūlymą patvirtinti ar atmesti gali tik Admin';
    end if;
    if new.kind = 'idea' and new.status not in ('pending', 'rejected') then new.status := 'pending'; end if;
    if new.kind = 'job' and new.status not in ('open', 'doing', 'done') then new.status := 'open'; end if;
    new.created_by := old.created_by; new.created_at := old.created_at;
  end if;
  if new.kind = 'job' and coalesce(array_length(new.assignees, 1), 0) > 0 and new.task_id is null then
    new.task_id := gen_random_uuid();
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists wh_jobs_guard on public.wh_jobs;
create trigger wh_jobs_guard before insert or update on public.wh_jobs
  for each row execute function public.wh_jobs_guard();

-- the job → a task of the people assigned (their calendar, tasks, reminder on the due day)
create or replace function public.wh_jobs_task() returns trigger
  language plpgsql security definer set search_path = public as $$
declare d jsonb := '{}'::jsonb; u uuid;
begin
  if tg_op = 'DELETE' then
    if old.task_id is not null then delete from public.tasks where id = old.task_id; end if;
    return old;
  end if;
  if new.task_id is null then return new; end if;
  if new.kind <> 'job' or coalesce(array_length(new.assignees, 1), 0) = 0 then
    delete from public.tasks where id = new.task_id;
    return new;
  end if;
  if new.status = 'done' then
    foreach u in array new.assignees loop d := d || jsonb_build_object(u::text, coalesce(new.done_at, now())); end loop;
  end if;
  insert into public.tasks (id, title, note, due_at, created_by, assignees, remind, done, updated_at)
  values (new.task_id,
          left('Sandėlio darbas: ' || new.title, 300),
          trim(both from concat_ws(E'\n\n', nullif(new.note, ''),
            'Prioritetas: ' || case new.priority when 1 then 'aukštas' when 2 then 'vidutinis' else 'žemas' end || ' · Sandėlis → Sandėlio darbai')),
          case when new.due_date is null then null else ((new.due_date + time '09:00') at time zone 'Europe/Vilnius') end,
          coalesce(case when tg_op = 'UPDATE' and new.assignees is distinct from old.assignees then auth.uid() end, new.created_by),
          new.assignees,
          case when new.due_date is null then '{}'::jsonb else '{"before":[0],"push":true}'::jsonb end,
          d, now())
  on conflict (id) do update set
    title = excluded.title, note = excluded.note, due_at = excluded.due_at, assignees = excluded.assignees,
    created_by = case when tg_op = 'UPDATE' and new.assignees is distinct from old.assignees then excluded.created_by else public.tasks.created_by end,
    remind = case when public.tasks.due_at is distinct from excluded.due_at then excluded.remind else public.tasks.remind end,
    sent = case when public.tasks.due_at is distinct from excluded.due_at then '{}'::jsonb else public.tasks.sent end,
    done = case when new.status = 'done' then excluded.done
                when tg_op = 'UPDATE' and old.status = 'done' then '{}'::jsonb else public.tasks.done end,
    updated_at = now();
  return new;
end $$;
drop trigger if exists wh_jobs_task on public.wh_jobs;
create trigger wh_jobs_task after insert or update or delete on public.wh_jobs
  for each row execute function public.wh_jobs_task();

-- everyone assigned ticked the task in their tasks / calendar → the warehouse job is done
create or replace function public.wh_task_done() returns trigger
  language plpgsql security definer set search_path = public as $$
declare j public.wh_jobs; who text;
begin
  if pg_trigger_depth() > 1 then return new; end if;
  select * into j from public.wh_jobs where task_id = new.id;
  if j.id is null or j.kind <> 'job' then return new; end if;
  if j.status in ('open', 'doing') and coalesce(array_length(j.assignees, 1), 0) > 0
     and not exists (select 1 from unnest(j.assignees) a where not (coalesce(new.done, '{}'::jsonb) ? a::text)) then
    select coalesce(nullif(trim(concat_ws(' ', first_name, last_name)), ''), full_name, '') into who from public.profiles where id = auth.uid();
    update public.wh_jobs set status = 'done', done_at = now(), done_by_name = who where id = j.id;
  elsif j.status = 'done' and coalesce(new.done, '{}'::jsonb) = '{}'::jsonb then
    update public.wh_jobs set status = 'open', done_at = null, done_by_name = null where id = j.id;
  end if;
  return new;
end $$;
drop trigger if exists wh_task_done on public.tasks;
create trigger wh_task_done after update of done on public.tasks
  for each row execute function public.wh_task_done();

-- files: equipment-photos/whjobs/<job id>/… – Tech and up, and the people assigned to that job
create or replace function public.equipment_photo_access(obj_name text, edit boolean) returns boolean
  language sql stable security definer set search_path = public as $$
  select case (storage.foldername(obj_name))[1]
    when 'rentals'   then case when edit then public.can_edit('rentals')   else public.can_view('rentals')   end
    when 'handovers' then case when edit then public.can_edit('handovers') else public.can_view('handovers') end
    when 'gear'      then public.can_view('inventory')
    when 'works'     then case when edit then public.can_edit('inventory') else public.can_view('inventory') end
    when 'whjobs'    then public.wh_can() or (not edit and exists (select 1 from public.wh_jobs j
                            where j.id::text = (storage.foldername(obj_name))[2] and (auth.uid() = any(j.assignees) or public.wh_asked(j.questions))))
    else false end
$$;
grant execute on function public.equipment_photo_access(text, boolean) to authenticated;

alter table public.wh_jobs replica identity full;
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'wh_jobs') then
    execute 'alter publication supabase_realtime add table public.wh_jobs';
  end if;
end $$;

notify pgrst, 'reload schema';
select 'wh_jobs ok' as result, (select count(*) from public.wh_jobs) as jobs;
