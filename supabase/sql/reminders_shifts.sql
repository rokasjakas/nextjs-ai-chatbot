-- ============================================================
-- reminders_shifts.sql — Admin → Priminimai → Team Tracker: dabar atidarytos pamainos (kam siunčiami priminimai).
-- time_shifts lentelės nariai tiesiogiai neskaito, todėl Admin gauna tik šį sąrašą (vardas, pradžia, kas pradėjo,
-- kada paskutinį kartą priminta). Saugu paleisti pakartotinai.
-- ============================================================
create or replace function public.rem_open_shifts() returns jsonb
  language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Matyti gali tik Admin.'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', s.id, 'name', m.name, 'started_at', s.started_at, 'started_by', s.started_by, 'reminded_at', s.reminded_at) order by s.started_at)
    from public.time_shifts s join public.tracker_members m on m.id = s.member_id where s.ended_at is null), '[]'::jsonb);
end $$;
revoke all on function public.rem_open_shifts() from public, anon;
grant execute on function public.rem_open_shifts() to authenticated;
notify pgrst, 'reload schema';
