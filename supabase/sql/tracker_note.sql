-- ============================================================
-- Team Tracker: dienos / pamainos komentaras
--  * time_shifts.note – ką darei tą dieną, pastabos (pvz. „vežta įranga į …“), iki 2000 simbolių
--  * tt_set_note(...) – komentarą įrašo / pakeičia pats narys (savo raktu) vykstančiai ar baigtai pamainai
--  * tt_shift_json – grąžina ir note (rodoma suvestinėse ir Excel)
-- Reikia: tracker.sql, tracker_loc.sql, tracker_edit.sql. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.time_shifts add column if not exists note text not null default '';

create or replace function public.tt_shift_json(sid uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', s.id, 'started_at', s.started_at, 'ended_at', s.ended_at,
    'start_loc', s.start_loc, 'end_loc', s.end_loc, 'start_edits', s.start_edits, 'note', s.note,
    'entries', coalesce((select jsonb_agg(jsonb_build_object('kind', e.kind, 'started_at', e.started_at, 'ended_at', e.ended_at) order by e.started_at)
                         from public.time_entries e where e.shift_id = s.id), '[]'::jsonb))
  from public.time_shifts s where s.id = sid
$$;

create or replace function public.tt_set_note(m uuid, p_token text, p_shift uuid, p_note text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select id into sid from public.time_shifts where id = p_shift and member_id = m;
  if sid is null then return jsonb_build_object('error', 'Tokios pamainos nėra.'); end if;
  update public.time_shifts set note = left(btrim(coalesce(p_note, '')), 2000) where id = sid;
  return public.tt_state_of(m) || jsonb_build_object('shift_saved', public.tt_shift_json(sid));
end $$;
revoke all on function public.tt_set_note(uuid, text, uuid, text) from public, anon;
grant execute on function public.tt_set_note(uuid, text, uuid, text) to authenticated;

notify pgrst, 'reload schema';
