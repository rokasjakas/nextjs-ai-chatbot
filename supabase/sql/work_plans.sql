-- ============================================================
-- „Darbų planas“
--  * work_plans – planas (pvz. „Automobilių priežiūra“): grupės (pvz. „Dokumentai ir privaloma įranga“)
--    su teiginiais (pvz. „Tech. pasas“, „Draudimo polisas“), kaip dažnai (kas dieną, darbo dienomis,
--    kas savaitę, kas mėnesį, kas N dienų, kartą), iki kada, kam priskirta
--    Kuria ir keičia tik Admin nariai; narys mato tik jam priskirtus planus
--  * work_plan_runs – nario užpildymas vienam laikotarpiui: kiekvienas teiginys Taip / Ne, komentaras,
--    nuotraukos. Kiekvieno pažymėjimo, komentaro ir nuotraukos laiką įrašo SERVERIS (ne telefonas)
--  * pateiktas (atliktas) užpildymas lieka archyve; Admin mato visus, narys – savo
--  * nuotraukos: saugykla 'work-files', kelias <nario id>/<užpildymo id>/<failas>
-- Reikia: user_roles.sql (is_admin, is_approved). Neatliktų darbų pranešimus siunčia „push-notify“ (cron).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.work_plans (
  id          uuid primary key default gen_random_uuid(),
  title       text not null,
  description text not null default '',
  groups      jsonb not null default '[]'::jsonb,      -- [{id, title, items:[{id, text, photo:'no'|'optional'|'required'}]}]
  freq        text not null default 'weekly' check (freq in ('daily','workdays','weekly','monthly','every_n','once')),
  weekday     smallint check (weekday is null or weekday between 1 and 7),   -- 1 = pirmadienis
  month_day   smallint check (month_day is null or month_day between 1 and 31),
  every_days  smallint check (every_days is null or every_days between 1 and 366),
  start_date  date not null default ((now() at time zone 'Europe/Vilnius')::date),
  due_time    text not null default '23:59' check (due_time ~ '^\d{2}:\d{2}$'),
  assignees   uuid[] not null default '{}',
  active      boolean not null default true,
  created_by  uuid default auth.uid(),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists work_plans_assignees on public.work_plans using gin (assignees);

create table if not exists public.work_plan_runs (
  id          uuid primary key default gen_random_uuid(),
  plan_id     uuid not null references public.work_plans(id) on delete cascade,
  user_id     uuid not null references auth.users(id) on delete cascade,
  period      date not null,                            -- the day the work belongs to (e.g. that Monday)
  due_at      timestamptz,
  answers     jsonb not null default '{}'::jsonb,       -- {itemId: {v:'yes'|'no', at, comment, comment_at, photos:[{path,name,at}]}}
  snapshot    jsonb,                                    -- the plan's title and groups as they were when filled in
  status      text not null default 'open' check (status in ('open','done')),
  started_at  timestamptz not null default now(),
  done_at     timestamptz,
  updated_at  timestamptz not null default now(),
  unique (plan_id, user_id, period)
);
create index if not exists work_plan_runs_user on public.work_plan_runs (user_id, period desc);
create index if not exists work_plan_runs_plan on public.work_plan_runs (plan_id, period desc);

-- who keeps the plans: Admin (any Admin level)
create or replace function public.wp_admin() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'admin' from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.wp_admin() to authenticated;

alter table public.work_plans enable row level security;
drop policy if exists "wp view" on public.work_plans;
create policy "wp view" on public.work_plans for select to authenticated
  using (public.wp_admin() or (public.is_approved() and auth.uid() = any(assignees)));
drop policy if exists "wp edit" on public.work_plans;
create policy "wp edit" on public.work_plans for all to authenticated
  using (public.wp_admin()) with check (public.wp_admin());
revoke all on public.work_plans from anon;
grant select, insert, update, delete on public.work_plans to authenticated;

alter table public.work_plan_runs enable row level security;
drop policy if exists "wpr view" on public.work_plan_runs;
create policy "wpr view" on public.work_plan_runs for select to authenticated
  using (user_id = auth.uid() or public.wp_admin());
drop policy if exists "wpr add" on public.work_plan_runs;
create policy "wpr add" on public.work_plan_runs for insert to authenticated
  with check (user_id = auth.uid() and status = 'open'
              and exists (select 1 from public.work_plans p where p.id = plan_id and p.active and auth.uid() = any(p.assignees)));
drop policy if exists "wpr fill" on public.work_plan_runs;
create policy "wpr fill" on public.work_plan_runs for update to authenticated
  using ((user_id = auth.uid() and status = 'open') or public.wp_admin())
  with check (user_id = auth.uid() or public.wp_admin());
drop policy if exists "wpr remove" on public.work_plan_runs;
create policy "wpr remove" on public.work_plan_runs for delete to authenticated
  using (public.wp_admin());
revoke all on public.work_plan_runs from anon;
grant select, insert, update, delete on public.work_plan_runs to authenticated;

-- the server's clock: when each answer, comment and photo was given, when it was handed in
create or replace function public.work_plan_runs_stamp() returns trigger
  language plpgsql set search_path = public as $$
declare k text; n jsonb; o jsonb; a jsonb := '{}'::jsonb; ts text := to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if tg_op = 'INSERT' then
    new.started_at := now(); new.done_at := null;
    if new.status = 'done' then new.status := 'open'; end if;
  end if;
  for k, n in select * from jsonb_each(coalesce(new.answers, '{}'::jsonb)) loop
    o := case when tg_op = 'UPDATE' then coalesce(old.answers -> k, '{}'::jsonb) else '{}'::jsonb end;
    if jsonb_typeof(n) <> 'object' then continue; end if;
    if (n ->> 'v') is distinct from (o ->> 'v') then n := n || jsonb_build_object('at', ts); else n := n || jsonb_build_object('at', o -> 'at'); end if;
    if coalesce(n ->> 'comment', '') is distinct from coalesce(o ->> 'comment', '') then n := n || jsonb_build_object('comment_at', ts); else n := n || jsonb_build_object('comment_at', o -> 'comment_at'); end if;
    -- a photo keeps the time it was first added
    n := n || jsonb_build_object('photos', coalesce((
      select jsonb_agg(case when exists (select 1 from jsonb_array_elements(coalesce(o -> 'photos', '[]'::jsonb)) op where op ->> 'path' = p ->> 'path')
                            then p || jsonb_build_object('at', (select op -> 'at' from jsonb_array_elements(o -> 'photos') op where op ->> 'path' = p ->> 'path' limit 1))
                            else p || jsonb_build_object('at', ts) end)
        from jsonb_array_elements(case when jsonb_typeof(n -> 'photos') = 'array' then n -> 'photos' else '[]'::jsonb end) p), '[]'::jsonb));
    a := a || jsonb_build_object(k, jsonb_strip_nulls(n));
  end loop;
  new.answers := a;
  if tg_op = 'UPDATE' then
    new.plan_id := old.plan_id; new.user_id := old.user_id; new.period := old.period; new.started_at := old.started_at;
    if new.status = 'done' and old.status <> 'done' then new.done_at := now();
    elsif new.status = 'open' then new.done_at := null;
    else new.done_at := old.done_at; end if;
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists work_plan_runs_stamp on public.work_plan_runs;
create trigger work_plan_runs_stamp before insert or update on public.work_plan_runs
  for each row execute function public.work_plan_runs_stamp();

create or replace function public.work_plans_touch() returns trigger
  language plpgsql set search_path = public as $$
begin
  new.updated_at := now();
  if tg_op = 'INSERT' then new.created_by := auth.uid(); new.created_at := now();
  else new.created_by := old.created_by; new.created_at := old.created_at; end if;
  return new;
end $$;
drop trigger if exists work_plans_touch on public.work_plans;
create trigger work_plans_touch before insert or update on public.work_plans
  for each row execute function public.work_plans_touch();

-- changes at once (Realtime)
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'work_plans') then
      execute 'alter publication supabase_realtime add table public.work_plans'; end if;
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'work_plan_runs') then
      execute 'alter publication supabase_realtime add table public.work_plan_runs'; end if;
  end if;
end $$;

-- photos
insert into storage.buckets (id, name, public) values ('work-files', 'work-files', false) on conflict (id) do nothing;
drop policy if exists "work files view" on storage.objects;
create policy "work files view" on storage.objects for select to authenticated
  using (bucket_id = 'work-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.wp_admin()));
drop policy if exists "work files add" on storage.objects;
create policy "work files add" on storage.objects for insert to authenticated
  with check (bucket_id = 'work-files' and (storage.foldername(name))[1] = auth.uid()::text and public.is_approved());
drop policy if exists "work files remove" on storage.objects;
create policy "work files remove" on storage.objects for delete to authenticated
  using (bucket_id = 'work-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.wp_admin()));

notify pgrst, 'reload schema';
