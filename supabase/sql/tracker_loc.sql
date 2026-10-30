-- ============================================================
-- Team Tracker: darbo pradžios ir pabaigos vieta
--  * time_shifts.start_loc / end_loc – {lat, lng, acc (m), addr} arba {err:'denied'|'fail'|'none'}
--  * tt_loc(...) – telefonas atsiunčia vietą paspaudus „Pradėti darbą“ / „Baigti darbą“
--  * tt_shift_json – pamainoje grąžina ir vietas (rodomos suvestinėse)
-- Reikia: tracker.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.time_shifts add column if not exists start_loc jsonb;
alter table public.time_shifts add column if not exists end_loc jsonb;

create or replace function public.tt_shift_json(sid uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', s.id, 'started_at', s.started_at, 'ended_at', s.ended_at,
    'start_loc', s.start_loc, 'end_loc', s.end_loc,
    'entries', coalesce((select jsonb_agg(jsonb_build_object('kind', e.kind, 'started_at', e.started_at, 'ended_at', e.ended_at) order by e.started_at)
                         from public.time_entries e where e.shift_id = s.id), '[]'::jsonb))
  from public.time_shifts s where s.id = sid
$$;

-- p_which: 'start' – ką tik pradėta pamaina; 'end' – ką tik baigta pamaina
create or replace function public.tt_loc(m uuid, p_token text, p_which text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid; loc jsonb;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  -- only the known keys, short values
  loc := jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20),
    'late', case when (p_loc->>'late') = 'true' then true end,
    'at', now()));
  if p_which = 'start' then
    select id into sid from public.time_shifts where member_id = m and start_loc is null and started_at > now() - interval '30 minutes'
      order by started_at desc limit 1;
    if sid is not null then update public.time_shifts set start_loc = loc where id = sid; end if;
  elsif p_which = 'end' then
    select id into sid from public.time_shifts where member_id = m and ended_at is not null and end_loc is null
      order by ended_at desc limit 1;
    if sid is not null then update public.time_shifts set end_loc = loc where id = sid; end if;
  end if;
  return jsonb_build_object('ok', sid is not null);
end $$;
revoke all on function public.tt_loc(uuid, text, text, jsonb) from public, anon;
grant execute on function public.tt_loc(uuid, text, text, jsonb) to authenticated;

notify pgrst, 'reload schema';
