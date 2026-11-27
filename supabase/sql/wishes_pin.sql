-- ============================================================
-- wishes_pin.sql — Linkėjimai: konkretus linkėjimas laikomas ekrane
--  * wish_boards.pinned – kol nustatyta, ekranas rodo tik tą linkėjimą; nuėmus – sklandžiai pereina prie kito ir sukasi toliau
--  * wish_admin: pin {board, id|null}; ištrintas ar nebe rodomas linkėjimas atsegamas pats
-- Reikia: wishes.sql … wishes_keep.sql. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.wish_boards add column if not exists pinned uuid references public.wishes(id) on delete set null;

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
      banned = case when a ? 'banned' then coalesce((select array_agg(distinct x) from (select left(lower(trim(e)), 60) x from jsonb_array_elements_text(a->'banned') e) q where x <> ''), '{}') else banned end
    where id = v_id returning * into b;
    return to_jsonb(b);
  elsif p_action = 'board_delete' then
    delete from public.wish_boards where id = v_id; return jsonb_build_object('ok', true);
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg((to_jsonb(w) - 'voter') || jsonb_build_object('counts', public.wish_rcounts(w.id)) order by coalesce(w.sort, extract(epoch from w.created_at)), w.created_at)
      from public.wishes w where w.board_id = (a->>'board')::uuid and w.status <> 'hidden'), '[]'::jsonb);
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

create or replace function public.wish_screen(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare b public.wish_boards;
begin
  if not public.poll_enabled() then return jsonb_build_object('off', true); end if;
  select * into b from public.wish_boards where screen_token = p_token;
  if b.id is null then return null; end if;
  return jsonb_build_object('name', b.name, 'brand', b.brand, 'w', b.w, 'h', b.h, 'interval_sec', b.interval_sec, 'pinned', b.pinned,
    'wishes', coalesce((select jsonb_agg(jsonb_build_object('id', w.id, 'text', w.text, 'name', w.name) order by w.sort, w.approved_at)
      from public.wishes w where w.board_id = b.id and w.status = 'approved'), '[]'::jsonb));
end $$;
revoke all on function public.wish_screen(text) from public;
grant execute on function public.wish_screen(text) to anon, authenticated;
notify pgrst, 'reload schema';
