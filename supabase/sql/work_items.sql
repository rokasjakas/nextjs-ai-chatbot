-- Darbų apskaita (1 etapas): darbo įrašas – vienas žmogus, viena diena, vienas renginys (ar kitas darbas be renginio).
-- * Savaime iš renginio komandos: žmogus pažymėtas „Užbookinta“ (reikšmė „gali“) → įrašas „Suplanuota“ su suma pagal
--   jo įkainį (Žmonės → stafkė, kitaip valandinis). Nuėmus „Užbookinta“ – suplanuotas įrašas išimamas.
-- * Ranka – „+ Darbas“ (sandėlis, vairavimas ir kt.).
-- * Kitą dieną po darbo – „Atlikta“ savaime (sąnaudos priskirtos renginiui); atsakingas pataiso išimtis.
-- * Sumas mato ir keičia Office, PV ir Admin (rates_access); Tech – kalendorių be sumų (work_calendar).
-- Būsenos: planned → done → invoiced → approved → paid (sąskaitos – 2 etapas); cancelled – nebuvo.

create table if not exists public.work_items (
  id          uuid primary key default gen_random_uuid(),
  event_id    text,                                   -- null: ne renginio darbas (bendros išlaidos)
  auto_key    text unique,                            -- iš renginio komandos: renginys|grupė|žmogus
  contact_id  text,
  person      text not null default '',
  work_date   date not null,
  time_text   text not null default '',
  kind        text not null default 'kita',
  place       text not null default '',
  pos         text not null default '',
  pay_type    text not null default 'day' check (pay_type in ('day','hour','fixed')),
  hours       numeric(6,2) check (hours is null or (hours >= 0 and hours < 1000)),
  rate        numeric(10,2) check (rate is null or (rate >= 0 and rate < 1000000)),
  amount      numeric(12,2) check (amount is null or (amount >= 0 and amount < 10000000)),
  extras      jsonb not null default '[]'::jsonb,     -- [{t, sum}] taksi, maistas…
  status      text not null default 'planned' check (status in ('planned','done','invoiced','approved','paid','cancelled')),
  invoice_id  uuid,
  edited      boolean not null default false,         -- pakeista ranka: komandos pakeitimai sumų nebeperrašo
  note        text not null default '',
  created_at  timestamptz not null default now(),
  created_by  uuid default auth.uid(),
  updated_at  timestamptz not null default now(),
  updated_by  uuid default auth.uid()
);
create index if not exists work_items_date_idx on public.work_items (work_date);
create index if not exists work_items_event_idx on public.work_items (event_id);
create index if not exists work_items_contact_idx on public.work_items (contact_id);

alter table public.work_items enable row level security;
drop policy if exists "work items office" on public.work_items;
create policy "work items office" on public.work_items for all to authenticated using (public.rates_access()) with check (public.rates_access());
revoke all on public.work_items from anon;
grant select, insert, update, delete on public.work_items to authenticated;

-- the day of a team group: its „diena, laikas“ cell („18d. 09:00–21:00“) in the event's month, else the event's date
create or replace function public.work_day_of(note text, ev_date date) returns date
  language plpgsql immutable as $$
declare d int; c date;
begin
  if ev_date is null then return null; end if;
  d := nullif(substring(coalesce(note, '') from '(\d{1,2})\s*d\.?'), '')::int;
  if d is null or d < 1 or d > 31 then return ev_date; end if;
  begin c := make_date(extract(year from ev_date)::int, extract(month from ev_date)::int, d); exception when others then return ev_date; end;
  if c > ev_date + 20 then c := (c - interval '1 month')::date; elsif c < ev_date - 20 then c := (c + interval '1 month')::date; end if;
  return c;
end $$;

-- an event's team → its work items (who is „Užbookinta“)
create or replace function public.work_items_from_event(p_id text, p_data jsonb, p_gone boolean) returns void
  language plpgsql security definer set search_path = public as $$
declare g jsonb; e jsonb; k text; keys text[] := '{}'; who text; ev_date date; d date; t text; kd text; cid text; r record; n int := 0;
begin
  if p_data ? 'handoverId' then return; end if;
  ev_date := nullif(p_data->>'date', '')::date;
  if not coalesce(p_gone, false) and ev_date is not null then
    for g in select * from jsonb_array_elements(coalesce(p_data->'crew', '[]'::jsonb)) loop
      n := n + 1;
      kd := case when p_data->>'kind' = 'work' then 'sandelis'
                 when lower(g->>'title') ~ 'demont' then 'demontazas'
                 when lower(g->>'title') ~ 'montav|montaz' then 'montazas'
                 when lower(g->>'title') ~ 'operator' then 'operatorius'
                 when lower(g->>'title') ~ 'budi' then 'aptarnavimas'
                 else 'kita' end;
      d := public.work_day_of(g->>'note', ev_date);
      t := coalesce(substring(coalesce(g->>'note', '') from '(\d{1,2}[:.]\d{2}(?:\s*[-–]\s*\d{1,2}[:.]\d{2})?)'), '');
      for e in select * from jsonb_array_elements(coalesce(g->'entries', '[]'::jsonb)) loop
        who := btrim(coalesce(e->>'person', ''));
        if who = '' or coalesce(e->>'status', '') <> 'gali' then continue; end if;
        k := p_id || '|' || coalesce(g->>'id', n::text) || '|' || lower(who);
        if k = any(keys) then continue; end if;
        keys := keys || k;
        select c.id into cid from public.contacts c
          where lower(btrim(coalesce(c.data->>'first', '') || ' ' || coalesce(c.data->>'last', ''))) = lower(who) limit 1;
        select cr.hourly, cr.daily into r from public.contact_rates cr where cr.contact_id = cid;
        insert into public.work_items (event_id, auto_key, contact_id, person, work_date, time_text, kind, pos, pay_type, rate, amount, created_by, updated_by)
          values (p_id, k, cid, who, d, t, kd, coalesce(e->>'pos', ''),
                  case when r.daily is not null or r.hourly is null then 'day' else 'hour' end,
                  coalesce(r.daily, r.hourly), r.daily, null, null)
          on conflict (auto_key) do update set
            person = excluded.person, work_date = excluded.work_date, time_text = excluded.time_text, kind = excluded.kind, pos = excluded.pos,
            contact_id = coalesce(public.work_items.contact_id, excluded.contact_id),
            status = case when public.work_items.status = 'cancelled' then 'planned' else public.work_items.status end,
            updated_at = now()
          where public.work_items.status in ('planned', 'cancelled');
      end loop;
    end loop;
  end if;
  -- no longer booked (or the event gone): a planned item goes; one already done stays and is marked for a look
  delete from public.work_items w where w.event_id = p_id and w.auto_key is not null and not (w.auto_key = any(keys)) and w.status = 'planned';
  update public.work_items w set status = 'cancelled', updated_at = now()
    where w.event_id = p_id and w.auto_key is not null and not (w.auto_key = any(keys)) and w.status = 'done' and w.invoice_id is null;
end $$;
revoke all on function public.work_items_from_event(text, jsonb, boolean) from public, anon, authenticated;

create or replace function public.events_work_items_trg() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'DELETE' then perform public.work_items_from_event(old.id, old.data, true); return old; end if;
  if tg_op = 'UPDATE' and new.data->'crew' is not distinct from old.data->'crew' and new.data->>'date' is not distinct from old.data->>'date'
     and new.data->>'status' is not distinct from old.data->>'status' and new.data->>'deletedAt' is not distinct from old.data->>'deletedAt' then return new; end if;
  perform public.work_items_from_event(new.id, new.data, coalesce(new.data->>'status', '') = 'cancel' or coalesce(new.data->>'deletedAt', '') <> '');
  return new;
exception when others then
  raise warning 'work_items: %', sqlerrm;   -- an event is saved whatever happens here
  return coalesce(new, old);
end $$;
drop trigger if exists events_work_items on public.events;
create trigger events_work_items after insert or update or delete on public.events for each row execute function public.events_work_items_trg();

-- the day after: „Atlikta“ (Vilnius time); called by the page and by the daily run
create or replace function public.work_items_mark_done() returns integer
  language sql security definer set search_path = public as $$
  with u as (update public.work_items set status = 'done', updated_at = now()
             where status = 'planned' and work_date < (now() at time zone 'Europe/Vilnius')::date returning 1)
  select count(*)::int from u
$$;
revoke all on function public.work_items_mark_done() from public, anon;
grant execute on function public.work_items_mark_done() to authenticated;

-- Tech and up: the calendar without the money
create or replace function public.work_calendar(p_from date, p_to date)
  returns table (id uuid, event_id text, person text, work_date date, time_text text, kind text, place text, pos text, status text)
  language sql stable security definer set search_path = public as $$
  select w.id, w.event_id, w.person, w.work_date, w.time_text, w.kind, w.place, w.pos, w.status from public.work_items w
   where w.work_date between p_from and p_to and w.status <> 'cancelled'
     and coalesce((select p.role in ('admin','pm','office','tech') from public.profiles p where p.id = auth.uid()), false)
$$;
revoke all on function public.work_calendar(date, date) from public, anon;
grant execute on function public.work_calendar(date, date) to authenticated;

-- the events already in the table: their booked people now
do $$ declare ev record; begin
  for ev in select id, data from public.events where nullif(data->>'date', '') is not null and (data->>'date')::date >= current_date - 60 loop
    perform public.work_items_from_event(ev.id, ev.data, coalesce(ev.data->>'status', '') = 'cancel' or coalesce(ev.data->>'deletedAt', '') <> '');
  end loop;
end $$;
select public.work_items_mark_done();

-- the daily „Atlikta“ (07:05 Vilnius ≈ 05:05 UTC)
do $$ begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.unschedule(jobid) from cron.job where jobname = 'work-items-done';
    perform cron.schedule('work-items-done', '5 5 * * *', 'select public.work_items_mark_done()');
  end if;
end $$;

notify pgrst, 'reload schema';
select 'work_items' as k, count(*)::text as v from public.work_items
union all select 'renginių su darbais', count(distinct event_id)::text from public.work_items;
