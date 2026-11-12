-- Darbų apskaita skaičiuojama nuo 2026-11-05 (savininko sprendimas): senesnių darbų sąskaitų nelaukiama – tokie įrašai
-- (be sąskaitos) ištrinami ir iš senų renginių nebeatsiranda. Data – app_config „labor_start“.
insert into public.app_config (key, value) values ('labor_start', '"2026-11-05"'::jsonb) on conflict (key) do update set value = excluded.value;
create or replace function public.wi_start() returns date
  language sql stable security definer set search_path = public as $$
  select coalesce((select nullif(value #>> '{}', '')::date from public.app_config where key = 'labor_start'), date '2026-11-05')
$$;

create or replace function public.work_items_from_event(p_id text, p_data jsonb, p_gone boolean) returns void
  language plpgsql security definer set search_path = public as $$
declare g jsonb; e jsonb; k text; keys text[] := '{}'; who text; nm text; ev_date date; d date; t text; kd text; cid text; rh numeric; rd numeric; n int := 0;
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
      if d < public.wi_start() then continue; end if;   -- Darbų apskaita runs from its start day (owner: 2026-11-05)
      t := coalesce(substring(coalesce(g->>'note', '') from '(\d{1,2}[:.]\d{2}(?:\s*[-–]\s*\d{1,2}[:.]\d{2})?)'), '');
      for e in select * from jsonb_array_elements(coalesce(g->'entries', '[]'::jsonb)) loop
        who := btrim(coalesce(e->>'person', ''));
        if public.wi_norm(who) = '' or public.wi_words(who) in ('visi', 'visi kiti', 'kiti', 'reikia', 'reikes', 'laisva') or coalesce(e->>'status', '') <> 'gali' or public.wi_member(who) then continue; end if;
        cid := null; nm := who;
        select c.id, c.name into cid, nm from public.wi_contact(who) c;
        if cid is null then nm := who; end if;
        k := p_id || '|' || coalesce(g->>'id', n::text) || '|' || coalesce(cid, public.wi_norm(who));
        if k = any(keys) then continue; end if;
        keys := keys || k;
        rh := null; rd := null;
        select cr.hourly, cr.daily into rh, rd from public.contact_rates cr where cr.contact_id = cid;
        insert into public.work_items (event_id, auto_key, contact_id, person, work_date, time_text, kind, pos, pay_type, rate, amount, note, created_by, updated_by)
          values (p_id, k, cid, nm, d, t, kd, coalesce(e->>'pos', ''),
                  case when rd is not null or rh is null then 'day' else 'hour' end,
                  coalesce(rd, rh), rd, case when cid is not null and public.wi_extra(who, nm) <> '' then 'Renginyje: ' || public.wi_extra(who, nm) else '' end, null, null)
          on conflict (auto_key) do update set
            person = excluded.person, contact_id = coalesce(excluded.contact_id, public.work_items.contact_id),
            work_date = case when public.work_items.status in ('planned', 'cancelled') then excluded.work_date else public.work_items.work_date end,
            time_text = case when public.work_items.status in ('planned', 'cancelled') then excluded.time_text else public.work_items.time_text end,
            kind = case when public.work_items.status in ('planned', 'cancelled') then excluded.kind else public.work_items.kind end,
            pos = case when public.work_items.status in ('planned', 'cancelled') then excluded.pos else public.work_items.pos end,
            status = case when public.work_items.status = 'cancelled' then (case when excluded.work_date < (now() at time zone 'Europe/Vilnius')::date then 'done' else 'planned' end) else public.work_items.status end,
            updated_at = now();
      end loop;
    end loop;
  end if;
  delete from public.work_items w where w.event_id = p_id and w.auto_key is not null and not (w.auto_key = any(keys)) and w.status = 'planned';
  update public.work_items w set status = 'cancelled', updated_at = now()
    where w.event_id = p_id and w.auto_key is not null and not (w.auto_key = any(keys)) and w.status = 'done' and w.invoice_id is null;
end $$;
revoke all on function public.work_items_from_event(text, jsonb, boolean) from public, anon, authenticated;

select 'ištrinta (senesni nei 2026-11-05, be sąskaitos)' as k, count(*)::text as v from public.work_items where work_date < public.wi_start() and invoice_id is null;
delete from public.work_items where work_date < public.wi_start() and invoice_id is null;
notify pgrst, 'reload schema';
select 'liko darbų įrašų' as k, count(*)::text as v from public.work_items
union all select 'laukia sąskaitos', count(*)::text from public.work_items where status = 'done' and invoice_id is null;
