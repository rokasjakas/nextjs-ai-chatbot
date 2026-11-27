-- ============================================================
-- wishes_auto.sql — Linkėjimai: automatinis patvirtinimas
--  * wish_boards.auto – kai įjungta, parašytas linkėjimas (praėjęs žodžių filtrą) iš karto patenka į ekraną, be ✓
--  * wish_admin board_update priima auto
-- Reikia: wishes.sql … wishes_rej.sql. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.wish_boards add column if not exists auto boolean not null default false;

create or replace function public.wish_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); b public.wish_boards; v_id uuid; v_new uuid; v_sort double precision;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  if p_action = 'boards' then
    return coalesce((select jsonb_agg(to_jsonb(x) || jsonb_build_object(
        'new', (select count(*) from public.wishes w where w.board_id = x.id and w.status = 'new'),
        'shown', (select count(*) from public.wishes w where w.board_id = x.id and w.status = 'approved')) order by x.created_at desc)
      from public.wish_boards x), '[]'::jsonb);
  elsif p_action = 'board_create' then
    insert into public.wish_boards (name) values (left(coalesce(nullif(trim(a->>'name'), ''), 'Linkėjimai'), 200)) returning * into b;
    return to_jsonb(b);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'board_update' then
    update public.wish_boards set
      name = left(coalesce(nullif(trim(a->>'name'), ''), name), 200),
      brand = coalesce(a->'brand', brand),
      w = coalesce((a->>'w')::int, w), h = coalesce((a->>'h')::int, h),
      interval_sec = coalesce((a->>'interval_sec')::int, interval_sec),
      open = coalesce((a->>'open')::boolean, open),
      filter = coalesce((a->>'filter')::boolean, filter),
      swear = coalesce((a->>'swear')::boolean, swear),
      reactions = coalesce((a->>'reactions')::boolean, reactions),
      auto = coalesce((a->>'auto')::boolean, auto),
      banned = case when a ? 'banned' then coalesce((select array_agg(distinct x) from (select left(lower(trim(e)), 60) x from jsonb_array_elements_text(a->'banned') e) q where x <> ''), '{}') else banned end
    where id = v_id returning * into b;
    return to_jsonb(b);
  elsif p_action = 'board_delete' then
    delete from public.wish_boards where id = v_id; return jsonb_build_object('ok', true);
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg((to_jsonb(w) - 'voter') || jsonb_build_object('counts', public.wish_rcounts(w.id)) order by coalesce(w.sort, extract(epoch from w.created_at)), w.created_at)
      from public.wishes w where w.board_id = (a->>'board')::uuid), '[]'::jsonb);
  elsif p_action = 'wish_update' then
    update public.wishes set text = left(coalesce(nullif(trim(a->>'text'), ''), text), 600),
      name = case when a ? 'name' then nullif(left(trim(a->>'name'), 80), '') else name end, edited = true
    where id = v_id; return jsonb_build_object('ok', true);
  elsif p_action = 'wish_status' then
    if coalesce(a->>'status', '') <> 'approved' then update public.wish_boards set pinned = null where pinned = v_id; end if;
    if coalesce(a->>'status', '') not in ('new','approved','hidden') then raise exception 'Neteisinga būsena'; end if;
    if a->>'status' = 'approved' then
      select coalesce(max(sort), 0) + 1 into v_sort from public.wishes where board_id = (select board_id from public.wishes where id = v_id) and status = 'approved';
      update public.wishes set status = 'approved', approved_at = now(), sort = v_sort where id = v_id;
    else update public.wishes set status = a->>'status' where id = v_id; end if;
    return jsonb_build_object('ok', true);
  elsif p_action = 'wish_sort' then
    update public.wishes set sort = (a->>'sort')::double precision where id = v_id; return jsonb_build_object('ok', true);
  elsif p_action = 'wish_delete' then
    -- never gone for good: moved to „Ištrinti“, from where it can be brought back
    update public.wish_boards set pinned = null where pinned = v_id;
    update public.wishes set status = 'hidden', hidden_at = now() where id = v_id; return jsonb_build_object('ok', true);
  elsif p_action = 'pin' then
    -- one wish held on the screen until let go (null lets go); only a wish shown on the screen
    update public.wish_boards set pinned = (select w.id from public.wishes w where w.id = v_id and w.board_id = (a->>'board')::uuid and w.status = 'approved')
      where id = (a->>'board')::uuid returning * into b;
    return to_jsonb(b);
  elsif p_action = 'trash' then
    return coalesce((select jsonb_agg((to_jsonb(w) - 'voter') || jsonb_build_object('counts', public.wish_rcounts(w.id)) order by w.hidden_at desc nulls last, w.created_at desc)
      from public.wishes w where w.board_id = (a->>'board')::uuid and w.status = 'hidden'), '[]'::jsonb);
  elsif p_action = 'wish_restore' then
    update public.wishes set status = 'new', hidden_at = null where id = v_id and status = 'hidden'; return jsonb_build_object('ok', true);
  elsif p_action = 'wish_add' then
    v_new := gen_random_uuid();
    select coalesce(max(sort), 0) + 1 into v_sort from public.wishes where board_id = (a->>'board')::uuid and status = 'approved';
    insert into public.wishes (id, board_id, text, name, status, sort, approved_at)
      values (v_new, (a->>'board')::uuid, left(trim(a->>'text'), 600), nullif(left(trim(coalesce(a->>'name', '')), 80), ''), 'approved', v_sort, now());
    return jsonb_build_object('id', v_new);
  end if;
  raise exception 'Nežinomas veiksmas';
end $$;
revoke all on function public.wish_admin(text, text, jsonb) from public;
grant execute on function public.wish_admin(text, text, jsonb) to anon, authenticated;

create or replace function public.wish_submit(p_token text, p_text text, p_name text default null, p_voter text default null) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare b public.wish_boards; t text := trim(coalesce(p_text, '')); n text := nullif(trim(coalesce(p_name, '')), '');
begin
  if not public.poll_enabled() then raise exception 'Linkėjimai išjungti'; end if;
  select * into b from public.wish_boards where submit_token = p_token;
  if b.id is null then raise exception 'Nuoroda nebegalioja'; end if;
  if not b.open then raise exception 'Linkėjimų rinkimas baigtas'; end if;
  if length(t) < 1 then raise exception 'Įrašyk linkėjimą'; end if;
  if length(t) > 400 then raise exception 'Per ilgas linkėjimas (daugiausia 400 simbolių)'; end if;
  if p_voter is not null and (select count(*) from public.wishes where board_id = b.id and voter = p_voter and created_at > now() - interval '5 minutes') >= 30 then
    raise exception 'Per daug linkėjimų iš karto – pabandyk po kelių minučių'; end if;
  if public.wish_bad_hit(t || ' ' || coalesce(n, ''), b.filter and b.swear, case when b.filter then b.banned else '{}' end) then
    raise exception 'Linkėjime yra neleistinų žodžių – pataisyk ir siųsk dar kartą'; end if;
  if (select count(*) from public.wishes where board_id = b.id and status = 'new') >= 3000 then raise exception 'Linkėjimų per daug'; end if;
  if b.auto then
    -- automatic: straight onto the screen (after the word filter), at the end of the order
    insert into public.wishes (board_id, text, name, voter, status, sort, approved_at)
      values (b.id, t, left(n, 80), left(p_voter, 40), 'approved',
        (select coalesce(max(sort), 0) + 1 from public.wishes where board_id = b.id and status = 'approved'), now());
  else
    insert into public.wishes (board_id, text, name, voter) values (b.id, t, left(n, 80), left(p_voter, 40));
  end if;
  return jsonb_build_object('ok', true);
end $$;
revoke all on function public.wish_submit(text, text, text, text) from public;
grant execute on function public.wish_submit(text, text, text, text) to anon, authenticated;
notify pgrst, 'reload schema';
