-- ============================================================
-- Team Tracker: darbo pradžios laiko pataisymas
--  * time_shifts.start_edits – pakeitimų žurnalas: [{from, to, note, loc, at, by}]
--    (loc – kur buvo telefonas, kai pradžia pakeista: {lat, lng, acc, addr} arba {err})
--  * tt_set_start(...) – vykstančios pamainos pradžią pakeičia pats narys (savo raktu);
--    ne vėlesnė nei pirmos veiklos pabaiga, ne ankstesnė nei ankstesnės pamainos pabaiga, ne senesnė nei 24 val.
--  * tt_shift_json – grąžina ir start_edits (rodoma suvestinėse ir Excel)
-- Reikia: tracker.sql, tracker_loc.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.time_shifts add column if not exists start_edits jsonb not null default '[]'::jsonb;

create or replace function public.tt_shift_json(sid uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', s.id, 'started_at', s.started_at, 'ended_at', s.ended_at,
    'start_loc', s.start_loc, 'end_loc', s.end_loc, 'start_edits', s.start_edits,
    'entries', coalesce((select jsonb_agg(jsonb_build_object('kind', e.kind, 'started_at', e.started_at, 'ended_at', e.ended_at) order by e.started_at)
                         from public.time_entries e where e.shift_id = s.id), '[]'::jsonb))
  from public.time_shifts s where s.id = sid
$$;

create or replace function public.tt_set_start(m uuid, p_token text, p_at timestamptz, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; fe public.time_entries; prev_end timestamptz; lim timestamptz; loc jsonb; nt text := left(btrim(coalesce(p_note, '')), 500);
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where member_id = m and ended_at is null;
  if s.id is null then return jsonb_build_object('error', 'Darbas nepradėtas.'); end if;
  if p_at is null then return jsonb_build_object('error', 'Nurodyk pradžios laiką.'); end if;
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

notify pgrst, 'reload schema';
