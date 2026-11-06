-- Darbų apskaita: vardas renginyje su papildomu tekstu („1. Augustas Ruseckas“, „CREW Oleg Zybailo vėlavo 10 min.“,
-- „Ernest Polito iki 18:00“, „VJ Martynas Ungurys“) – žmogus randamas pagal vardą ir pavardę tekste (Žmonėse ar tarp narių);
-- papildomas tekstas – į darbo įrašo pastabas. Registruoti nariai neįtraukiami (savininko sprendimas), dublikatai sujungiami.

-- the words of a text: lower case, no accents, no punctuation
create or replace function public.wi_words(t text) returns text
  language sql immutable as $$
  select btrim(regexp_replace(translate(lower(coalesce(t, '')), 'ąčęėįšųūžéèàáóöüäõ', 'aceeisuuzeeaaoouao'), '[^a-z0-9]+', ' ', 'g'))
$$;
-- „first last“ (or „last first“, or written together) inside the text
create or replace function public.wi_has(txt text, first text, last text) returns boolean
  language sql immutable as $$
  select public.wi_words(first) <> '' and public.wi_words(last) <> '' and (
       position(' ' || public.wi_words(first || ' ' || last) || ' ' in ' ' || public.wi_words(txt) || ' ') > 0
    or position(' ' || public.wi_words(last || ' ' || first) || ' ' in ' ' || public.wi_words(txt) || ' ') > 0
    or public.wi_norm(txt) in (public.wi_norm(first || last), public.wi_norm(last || first)))
$$;

create or replace function public.wi_contact(who text) returns table (id text, name text)
  language sql stable security definer set search_path = public as $$
  select c.id, btrim(coalesce(c.data->>'first', '') || ' ' || coalesce(c.data->>'last', ''))
    from public.contacts c
   where public.wi_has(who, c.data->>'first', c.data->>'last')
   order by length(coalesce(c.data->>'first', '') || coalesce(c.data->>'last', '')) desc, coalesce((c.data->>'inactive')::boolean, false), c.id
   limit 1
$$;
revoke all on function public.wi_contact(text) from public, anon;

create or replace function public.wi_member(who text) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles p
   where coalesce(p.role, '') not in ('', 'pending', 'blocked')
     and (public.wi_has(who, p.first_name, p.last_name)
       or (public.wi_words(p.full_name) like '% %' and position(' ' || public.wi_words(p.full_name) || ' ' in ' ' || public.wi_words(who) || ' ') > 0)
       or (nullif(public.wi_norm(to_jsonb(p)->>'nickname'), '') is not null and public.wi_norm(who) = public.wi_norm(to_jsonb(p)->>'nickname'))))
$$;
revoke all on function public.wi_member(text) from public, anon;

-- the extra words next to the name („vėlavo 10 min.“) – kept in the note of an item made from the team
create or replace function public.wi_extra(who text, nm text) returns text
  language sql immutable as $$
  select case when public.wi_words(who) = public.wi_words(nm) or public.wi_norm(who) = public.wi_norm(nm) then '' else btrim(who) end
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

-- the members' items made already: out (changed by hand – kept, as hand-made)
create temporary table wi_mem as select id, edited from public.work_items where auto_key is not null and invoice_id is null and public.wi_member(person);
select 'nariai: išimta' as k, count(*)::text as v from wi_mem where not edited
union all select 'nariai: palikta (taisyta ranka)', count(*)::text from wi_mem where edited;
delete from public.work_items where id in (select id from wi_mem where not edited);
update public.work_items set auto_key = null where id in (select id from wi_mem where edited);
drop table wi_mem;

-- the items made already: the new key (event | group | person in Žmonės or the tidied name); the same key twice – one stays
drop table if exists pg_temp.wi_map, pg_temp.wi_gone;
create temporary table wi_map as
  select w.id, w.status, w.edited, w.invoice_id, w.created_at,
         split_part(w.auto_key, '|', 1) || '|' || split_part(w.auto_key, '|', 2) || '|' || coalesce(c.id, public.wi_norm(w.person)) as nk,
         c.id as cid, coalesce(c.name, w.person) as nm
    from public.work_items w left join lateral public.wi_contact(w.person) c on true
   where w.auto_key is not null;
create temporary table wi_gone as
  select id from (select id, invoice_id, row_number() over (partition by nk order by (invoice_id is not null) desc, edited desc,
                    array_position(array['paid','approved','invoiced','done','planned','cancelled'], status), created_at) as rn from wi_map) x
   where rn > 1 and invoice_id is null;
select 'sujungta (dublikatai išimti)' as k, count(*)::text as v from wi_gone;
delete from public.work_items where id in (select id from wi_gone);
update public.work_items w set auto_key = 'tmp|' || w.id::text where w.id in (select id from wi_map);
update public.work_items w set auto_key = m.nk, contact_id = coalesce(m.cid, w.contact_id), person = m.nm,
       note = case when w.note = '' and public.wi_extra(w.person, m.nm) <> '' then 'Renginyje: ' || public.wi_extra(w.person, m.nm) else w.note end
  from wi_map m where m.id = w.id;
-- the hand-made ones: the name as in Žmonės too
update public.work_items w set (contact_id, person) = (select c.id, c.name from public.wi_contact(w.person) c)
 where w.auto_key is null and w.contact_id is null and exists (select 1 from public.wi_contact(w.person));
drop table if exists pg_temp.wi_map, pg_temp.wi_gone;

do $$ declare ev record; begin
  for ev in select id, data from public.events where nullif(data->>'date', '') is not null and (data->>'date')::date >= current_date - 60 loop
    perform public.work_items_from_event(ev.id, ev.data, coalesce(ev.data->>'status', '') = 'cancel' or coalesce(ev.data->>'deletedAt', '') <> '');
  end loop;
end $$;
select public.work_items_mark_done();

notify pgrst, 'reload schema';
select 'darbų įrašų' as k, count(*)::text as v from public.work_items
union all select 'nerasti Žmonėse (vardų)', count(distinct public.wi_norm(person))::text from public.work_items where contact_id is null
union all select 'nerasti vardai', coalesce(string_agg(distinct person, ', '), '') from (select person from public.work_items where contact_id is null order by person limit 400) x;
