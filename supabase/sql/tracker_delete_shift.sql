-- ============================================================
-- Team Tracker: savo pamainos ištrynimas
--  * tt_delete_shift(...) – narys (savo raktu) ištrina savo BAIGTĄ pamainą (ne senesnę nei 30 d.);
--    komentaras būtinas, užfiksuojama vieta
--  * ištrinta pamaina (su visomis veiklomis), komentaras, vieta, kada ir kas – lieka žurnale time_shift_deletions
--  * tt_report grąžina ir to laikotarpio ištrintas pamainas ('deleted') – vadovai mato, kas ištrinta ir kodėl
-- Reikia: tracker.sql, tracker_edit.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.time_shift_deletions (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references public.tracker_members(id) on delete cascade,
  shift jsonb not null,
  note text not null,
  loc jsonb,
  at timestamptz not null default now(),
  by uuid
);
create index if not exists time_shift_deletions_member on public.time_shift_deletions(member_id, at);
alter table public.time_shift_deletions enable row level security;   -- read only through tt_report

create or replace function public.tt_delete_shift(m uuid, p_token text, p_shift uuid, p_note text, p_loc jsonb) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; s public.time_shifts; loc jsonb; nt text := left(btrim(coalesce(p_note, '')), 500);
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select * into s from public.time_shifts where id = p_shift and member_id = m;
  if s.id is null then return jsonb_build_object('error', 'Tokios pamainos nėra.'); end if;
  if s.ended_at is null then return jsonb_build_object('error', 'Vykstančios pamainos ištrinti negalima – pirma baik darbą.'); end if;
  if s.started_at < now() - interval '30 days' then return jsonb_build_object('error', 'Ištrinti galima tik pastarųjų 30 d. pamainas.'); end if;
  if char_length(nt) < 3 then return jsonb_build_object('error', 'Parašyk komentarą – kodėl trini pamainą.'); end if;
  loc := jsonb_strip_nulls(jsonb_build_object(
    'lat', case when jsonb_typeof(p_loc->'lat') = 'number' then round((p_loc->>'lat')::numeric, 6) end,
    'lng', case when jsonb_typeof(p_loc->'lng') = 'number' then round((p_loc->>'lng')::numeric, 6) end,
    'acc', case when jsonb_typeof(p_loc->'acc') = 'number' then round((p_loc->>'acc')::numeric) end,
    'addr', left(p_loc->>'addr', 160),
    'err', left(p_loc->>'err', 20)));
  insert into public.time_shift_deletions(member_id, shift, note, loc, by)
    values (m, public.tt_shift_json(s.id), nt, case when loc = '{}'::jsonb then null else loc end, auth.uid());
  delete from public.time_entries where shift_id = s.id;
  delete from public.time_shifts where id = s.id;
  return public.tt_state_of(m);
end $$;
revoke all on function public.tt_delete_shift(uuid, text, uuid, text, jsonb) from public, anon;
grant execute on function public.tt_delete_shift(uuid, text, uuid, text, jsonb) to authenticated;

create or replace function public.tt_report(m uuid, p_token text, p_from timestamptz, p_to timestamptz) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, true);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shifts', coalesce((select jsonb_agg(public.tt_shift_json(s.id) order by s.started_at desc) from public.time_shifts s
       where s.member_id = m and s.started_at < p_to and coalesce(s.ended_at, now()) > p_from), '[]'::jsonb),
    'deleted', coalesce((select jsonb_agg(jsonb_build_object('shift', d.shift, 'note', d.note, 'loc', d.loc, 'at', d.at) order by d.at desc)
       from public.time_shift_deletions d
       where d.member_id = m and (d.shift->>'started_at')::timestamptz < p_to and coalesce((d.shift->>'ended_at')::timestamptz, d.at) > p_from), '[]'::jsonb));
end $$;

notify pgrst, 'reload schema';
