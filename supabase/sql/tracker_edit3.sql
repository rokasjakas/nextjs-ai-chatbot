-- ============================================================
-- Team Tracker: komentaras būtinas keičiant pradžios / pabaigos laiką
--  * tt_set_start ir tt_edit_shift atmeta pakeitimą be komentaro (bent 3 simboliai)
--  * tt_edit_shift: keičiant tik pradžią arba tik pabaigą, kitas laikas lieka tiksliai toks, koks buvo
--    (nebeapvalinamas iki minutės ir nebeįrašomas į žurnalą kaip pakeistas)
--  * persidengimo klaida nurodo, su kuria pamaina (diena ir laikas)
--  * tikrinamas tik keičiamas laikas (keičiant pradžią nebetikrinama pabaiga ir atvirkščiai);
--    programa laiką siunčia milisekundžių tikslumu, todėl laikas, besiskiriantis < 1 ms, laikomas nepakeistu
-- Reikia: tracker_edit.sql, tracker_edit2.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.tt_set_start(m uuid, p_token text, p_at timestamptz, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; fe public.time_entries; prev_end timestamptz; lim timestamptz; loc jsonb; nt text := left(btrim(coalesce(p_note, '')), 500);
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where member_id = m and ended_at is null;
  if s.id is null then return jsonb_build_object('error', 'Darbas nepradėtas.'); end if;
  if p_at is null then return jsonb_build_object('error', 'Nurodyk pradžios laiką.'); end if;
  if char_length(nt) < 3 then return jsonb_build_object('error', 'Parašyk komentarą – kodėl keiti laiką.'); end if;
  p_at := date_trunc('minute', p_at);
  select * into fe from public.time_entries where shift_id = s.id order by started_at limit 1;
  lim := coalesce(fe.ended_at, now());
  if p_at > lim then
    return jsonb_build_object('error', case when fe.ended_at is null then 'Pradžia negali būti vėlesnė nei dabar.' else 'Pradžia negali būti vėlesnė nei pirmos veiklos pabaiga ('||to_char(fe.ended_at at time zone 'Europe/Vilnius', 'HH24:MI')||').' end);
  end if;
  if p_at < now() - interval '24 hours' then return jsonb_build_object('error', 'Pradžią galima paankstinti ne daugiau kaip 24 val.'); end if;
  select max(ended_at) into prev_end from public.time_shifts where member_id = m and id <> s.id and ended_at is not null;
  if prev_end is not null and p_at < prev_end then
    return jsonb_build_object('error', 'Pradžia negali būti ankstesnė nei ankstesnės pamainos pabaiga ('||to_char(prev_end at time zone 'Europe/Vilnius', 'YYYY-MM-DD HH24:MI')||').');
  end if;
  if p_at = s.started_at then return public.tt_state_of(m); end if;
  loc := jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20)));
  update public.time_entries set started_at = p_at where id = fe.id;
  update public.time_shifts set started_at = p_at,
    start_edits = coalesce(start_edits, '[]'::jsonb) || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
      'from', s.started_at, 'to', p_at, 'note', nullif(nt, ''), 'loc', case when loc = '{}'::jsonb then null else loc end, 'at', now(), 'by', auth.uid())))
  where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_set_start(uuid, text, timestamptz, text, jsonb) from public, anon;
grant execute on function public.tt_set_start(uuid, text, timestamptz, text, jsonb) to authenticated;


create or replace function public.tt_edit_shift(m uuid, p_token text, p_shift uuid, p_start timestamptz, p_end timestamptz, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; fe public.time_entries; le public.time_entries; n int; loc jsonb; ed jsonb;
        nt text := left(btrim(coalesce(p_note, '')), 500); vs text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where id = p_shift and member_id = m;
  if s.id is null then return jsonb_build_object('error', 'Tokios pamainos nėra.'); end if;
  if s.ended_at is null then return jsonb_build_object('error', 'Pamaina dar vyksta – pradžią keisk per „✎ Pakeisti pradžios laiką“.'); end if;
  if s.started_at < now() - interval '30 days' then return jsonb_build_object('error', 'Taisyti galima tik pastarųjų 30 d. pamainas.'); end if;
  if p_start is null or p_end is null then return jsonb_build_object('error', 'Nurodyk pradžios ir pabaigos laiką.'); end if;
  if char_length(nt) < 3 then return jsonb_build_object('error', 'Parašyk komentarą – kodėl keiti laiką.'); end if;
  -- the app sends times to the millisecond, the database keeps microseconds: a time within 1 ms of the saved one is not changed
  if abs(extract(epoch from p_start - s.started_at)) < 0.001 then p_start := s.started_at; end if;
  if abs(extract(epoch from p_end - s.ended_at)) < 0.001 then p_end := s.ended_at; end if;
  -- only a time that is really changed is rounded to the minute (the other one stays exactly as it was)
  if p_start <> s.started_at then p_start := date_trunc('minute', p_start); end if;
  if p_end <> s.ended_at then p_end := date_trunc('minute', p_end); end if;
  if p_end <= p_start then return jsonb_build_object('error', 'Pabaiga turi būti vėlesnė nei pradžia.'); end if;
  if p_end > now() then return jsonb_build_object('error', 'Pabaiga negali būti vėlesnė nei dabar.'); end if;
  if p_end - p_start > interval '36 hours' then return jsonb_build_object('error', 'Pamaina negali būti ilgesnė nei 36 val.'); end if;
  select string_agg(to_char(o.started_at at time zone 'Europe/Vilnius', 'MM-DD HH24:MI')||' – '||coalesce(to_char(o.ended_at at time zone 'Europe/Vilnius', 'HH24:MI'), 'vyksta'), ', ' order by o.started_at)
    into vs from public.time_shifts o where o.member_id = m and o.id <> s.id
             and o.started_at < p_end and coalesce(o.ended_at, now()) > p_start;
  if vs is not null then
    return jsonb_build_object('error', 'Šis laikas persidengia su kita tavo pamaina: '||vs||'. Pirma pataisyk tą pamainą.');
  end if;
  select count(*) into n from public.time_entries where shift_id = s.id;
  select * into fe from public.time_entries where shift_id = s.id order by started_at limit 1;
  select * into le from public.time_entries where shift_id = s.id order by started_at desc limit 1;
  -- only the time that is changed is checked against the activities (the other one stays as it was)
  if n > 1 then
    if p_start <> s.started_at and p_start >= fe.ended_at then
      return jsonb_build_object('error', 'Pradžia negali būti vėlesnė nei pirmos veiklos pabaiga ('||to_char(fe.ended_at at time zone 'Europe/Vilnius', 'HH24:MI')||').');
    end if;
    if p_end <> s.ended_at and p_end <= le.started_at then
      return jsonb_build_object('error', 'Pabaiga negali būti ankstesnė nei paskutinės veiklos pradžia ('||to_char(le.started_at at time zone 'Europe/Vilnius', 'HH24:MI')||').');
    end if;
  end if;
  if p_start = s.started_at and p_end = s.ended_at then return public.tt_state_of(m); end if;
  loc := jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20)));
  ed := jsonb_strip_nulls(jsonb_build_object(
    'from', case when p_start <> s.started_at then s.started_at end, 'to', case when p_start <> s.started_at then p_start end,
    'end_from', case when p_end <> s.ended_at then s.ended_at end, 'end_to', case when p_end <> s.ended_at then p_end end,
    'note', nullif(nt, ''), 'loc', case when loc = '{}'::jsonb then null else loc end, 'at', now(), 'by', auth.uid()));
  update public.time_entries set started_at = p_start where id = fe.id;
  update public.time_entries set ended_at = p_end where id = le.id;
  update public.time_shifts set started_at = p_start, ended_at = p_end,
    start_edits = coalesce(start_edits, '[]'::jsonb) || jsonb_build_array(ed)
  where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_edit_shift(uuid, text, uuid, timestamptz, timestamptz, text, jsonb) from public, anon;
grant execute on function public.tt_edit_shift(uuid, text, uuid, timestamptz, timestamptz, text, jsonb) to authenticated;


notify pgrst, 'reload schema';
