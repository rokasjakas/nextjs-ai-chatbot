-- ============================================================
-- Team Tracker: laisvas pradžios / pabaigos keitimas, komentaras būtinas
--  * tt_set_start (vykstanti pamaina) ir tt_edit_shift (baigta pamaina): laiką galima keisti kaip nori,
--    būtinas tik komentaras (bent 3 simboliai); lieka tik: pabaiga po pradžios, ne ateityje,
--    ir pamaina neuždengia kitos tavo pamainos (klaida nurodo, kurios)
--  * veiklos prisitaiko: pirma prasideda nuo naujos pradžios, paskutinė baigiasi naujos pabaigos metu,
--    veiklos už naujų ribų nukerpamos (jei nelieka nė vienos – lieka viena per visą pamainą)
--  * keičiant tik pradžią ar tik pabaigą, kitas laikas lieka toks, koks buvo (< 1 ms skirtumas – nepakeista)
--  * kiekvienas pakeitimas su komentaru, vieta, kada ir kas – žurnale time_shifts.start_edits
-- Reikia: tracker_edit.sql, tracker_edit2.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- the place where the change was made, cleaned up
create or replace function public.tt_loc_clean(p_loc jsonb) returns jsonb
  language sql immutable as $$
  select nullif(jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20))), '{}'::jsonb)
$$;

-- the other shifts of the member that a time span would cover (empty – none)
create or replace function public.tt_overlaps(m uuid, sid uuid, a timestamptz, z timestamptz) returns text
  language sql stable security definer set search_path = public as $$
  select string_agg(to_char(o.started_at at time zone 'Europe/Vilnius', 'MM-DD HH24:MI')||' – '||coalesce(to_char(o.ended_at at time zone 'Europe/Vilnius', 'HH24:MI'), 'vyksta'), ', ' order by o.started_at)
  from public.time_shifts o where o.member_id = m and o.id <> sid and o.started_at < z and coalesce(o.ended_at, now()) > a
$$;

-- the activities follow the shift's new bounds
create or replace function public.tt_fit_entries(sid uuid, a timestamptz, z timestamptz, kind0 text) returns void
  language plpgsql security definer set search_path = public as $$
declare fid uuid; lid uuid;
begin
  -- what is wholly outside the new span goes (the running activity – ended_at null – stays while the shift runs)
  delete from public.time_entries where shift_id = sid and ((ended_at is not null and ended_at <= a) or (z is not null and started_at >= z));
  if not exists (select 1 from public.time_entries where shift_id = sid) then
    insert into public.time_entries(shift_id, kind, started_at, ended_at) values (sid, coalesce(kind0, 'warehouse'), a, z);
    return;
  end if;
  select id into fid from public.time_entries where shift_id = sid order by started_at limit 1;
  update public.time_entries set started_at = a where id = fid;
  if z is not null then
    select id into lid from public.time_entries where shift_id = sid order by started_at desc limit 1;
    update public.time_entries set ended_at = z where id = lid;
  end if;
end $$;
revoke all on function public.tt_overlaps(uuid, uuid, timestamptz, timestamptz), public.tt_fit_entries(uuid, timestamptz, timestamptz, text) from public, anon, authenticated;

create or replace function public.tt_set_start(m uuid, p_token text, p_at timestamptz, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; k0 text; vs text; nt text := left(btrim(coalesce(p_note, '')), 500);
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where member_id = m and ended_at is null;
  if s.id is null then return jsonb_build_object('error', 'Darbas nepradėtas.'); end if;
  if p_at is null then return jsonb_build_object('error', 'Nurodyk pradžios laiką.'); end if;
  if char_length(nt) < 3 then return jsonb_build_object('error', 'Parašyk komentarą – kodėl keiti laiką.'); end if;
  if abs(extract(epoch from p_at - s.started_at)) < 0.001 then return public.tt_state_of(m); end if;
  p_at := date_trunc('minute', p_at);
  if p_at > now() then return jsonb_build_object('error', 'Pradžia negali būti vėlesnė nei dabar.'); end if;
  vs := public.tt_overlaps(m, s.id, p_at, now());
  if vs is not null then return jsonb_build_object('error', 'Šis laikas persidengia su kita tavo pamaina: '||vs||'. Pirma pataisyk ar ištrink tą pamainą.'); end if;
  select kind into k0 from public.time_entries where shift_id = s.id order by started_at limit 1;
  perform public.tt_fit_entries(s.id, p_at, null, k0);
  update public.time_shifts set started_at = p_at,
    start_edits = coalesce(start_edits, '[]'::jsonb) || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
      'from', s.started_at, 'to', p_at, 'note', nt, 'loc', public.tt_loc_clean(p_loc), 'at', now(), 'by', auth.uid())))
  where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_set_start(uuid, text, timestamptz, text, jsonb) from public, anon;
grant execute on function public.tt_set_start(uuid, text, timestamptz, text, jsonb) to authenticated;

create or replace function public.tt_edit_shift(m uuid, p_token text, p_shift uuid, p_start timestamptz, p_end timestamptz, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; k0 text; vs text; nt text := left(btrim(coalesce(p_note, '')), 500);
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where id = p_shift and member_id = m;
  if s.id is null then return jsonb_build_object('error', 'Tokios pamainos nėra.'); end if;
  if s.ended_at is null then return jsonb_build_object('error', 'Pamaina dar vyksta – pradžią keisk per „✎ Pakeisti pradžios laiką“.'); end if;
  if p_start is null or p_end is null then return jsonb_build_object('error', 'Nurodyk pradžios ir pabaigos laiką.'); end if;
  if char_length(nt) < 3 then return jsonb_build_object('error', 'Parašyk komentarą – kodėl keiti laiką.'); end if;
  -- what is not changed stays exactly as it was (the app sends milliseconds, the database keeps microseconds)
  if abs(extract(epoch from p_start - s.started_at)) < 0.001 then p_start := s.started_at; else p_start := date_trunc('minute', p_start); end if;
  if abs(extract(epoch from p_end - s.ended_at)) < 0.001 then p_end := s.ended_at; else p_end := date_trunc('minute', p_end); end if;
  if p_start = s.started_at and p_end = s.ended_at then return public.tt_state_of(m); end if;
  if p_end <= p_start then return jsonb_build_object('error', 'Pabaiga turi būti vėlesnė nei pradžia.'); end if;
  if p_end > now() then return jsonb_build_object('error', 'Pabaiga negali būti vėlesnė nei dabar.'); end if;
  vs := public.tt_overlaps(m, s.id, p_start, p_end);
  if vs is not null then return jsonb_build_object('error', 'Šis laikas persidengia su kita tavo pamaina: '||vs||'. Pirma pataisyk ar ištrink tą pamainą.'); end if;
  select kind into k0 from public.time_entries where shift_id = s.id order by started_at limit 1;
  perform public.tt_fit_entries(s.id, p_start, p_end, k0);
  update public.time_shifts set started_at = p_start, ended_at = p_end,
    start_edits = coalesce(start_edits, '[]'::jsonb) || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
      'from', case when p_start <> s.started_at then s.started_at end, 'to', case when p_start <> s.started_at then p_start end,
      'end_from', case when p_end <> s.ended_at then s.ended_at end, 'end_to', case when p_end <> s.ended_at then p_end end,
      'note', nt, 'loc', public.tt_loc_clean(p_loc), 'at', now(), 'by', auth.uid())))
  where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_edit_shift(uuid, text, uuid, timestamptz, timestamptz, text, jsonb) from public, anon;
grant execute on function public.tt_edit_shift(uuid, text, uuid, timestamptz, timestamptz, text, jsonb) to authenticated;

notify pgrst, 'reload schema';
