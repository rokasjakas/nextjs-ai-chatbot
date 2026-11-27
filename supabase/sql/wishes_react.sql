-- ============================================================
-- wishes_react.sql — Linkėjimai: emoji reakcijos
--  * kai įjungta (wish_boards.reactions), nuskenavę QR mato ekrane rodomus linkėjimus ir gali paspausti emoji
--    (tik geros emocijos: ❤️ 😍 😊 😂 🎉 👏 👍 🥂 🤗 🌟); vienas žmogus – kiekvieną emoji vieną kartą (paspaudus dar kartą – atšaukia)
--  * valdymo puslapio sąraše – kiek kokių reakcijų gavo kiekvienas linkėjimas
-- Reikia: wishes.sql, wishes_mod.sql, wishes_mod2.sql. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.wish_boards add column if not exists reactions boolean not null default false;
create table if not exists public.wish_reactions (
  wish_id     uuid not null references public.wishes(id) on delete cascade,
  voter       text not null,
  emoji       text not null,
  created_at  timestamptz not null default now(),
  primary key (wish_id, voter, emoji)
);
alter table public.wish_reactions enable row level security;
revoke all on public.wish_reactions from anon, authenticated;

create or replace function public.wish_emojis() returns text[] language sql immutable as $$
  select array['heart','love','smile','laugh','party','clap','like','cheers','hug','star'];
$$;
-- how many of each emoji a wish has: {"heart": 3, "party": 1}
create or replace function public.wish_rcounts(p_wish uuid) returns jsonb language sql stable security definer set search_path = public as $$
  select coalesce(jsonb_object_agg(emoji, c), '{}'::jsonb) from (select emoji, count(*) c from public.wish_reactions where wish_id = p_wish group by emoji) q;
$$;
revoke all on function public.wish_rcounts(uuid) from public;

-- the phone: the wishes shown on the screen (newest first), their emoji and the ones this phone pressed
create or replace function public.wish_feed(p_token text, p_voter text default null) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare b public.wish_boards;
begin
  if not public.poll_enabled() then return jsonb_build_object('off', true); end if;
  select * into b from public.wish_boards where submit_token = p_token;
  if b.id is null then return null; end if;
  if not b.reactions then return jsonb_build_object('reactions', false); end if;
  return jsonb_build_object('reactions', true, 'wishes', coalesce((select jsonb_agg(jsonb_build_object('id', w.id, 'text', w.text, 'name', w.name,
      'counts', public.wish_rcounts(w.id),
      'mine', coalesce((select jsonb_agg(r.emoji) from public.wish_reactions r where r.wish_id = w.id and r.voter = p_voter), '[]'::jsonb))
    order by w.approved_at desc nulls last, w.created_at desc)
    from public.wishes w where w.board_id = b.id and w.status = 'approved'), '[]'::jsonb));
end $$;
revoke all on function public.wish_feed(text, text) from public;
grant execute on function public.wish_feed(text, text) to anon, authenticated;

-- an emoji pressed on a phone: on, or off when pressed again; at most 300 in 10 minutes from one phone
create or replace function public.wish_react(p_token text, p_wish uuid, p_emoji text, p_voter text) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare b public.wish_boards; v text := left(trim(coalesce(p_voter, '')), 40);
begin
  if not public.poll_enabled() then raise exception 'Linkėjimai išjungti'; end if;
  select * into b from public.wish_boards where submit_token = p_token;
  if b.id is null then raise exception 'Nuoroda nebegalioja'; end if;
  if not b.reactions then raise exception 'Reakcijos išjungtos'; end if;
  if v = '' then raise exception 'Nežinomas telefonas'; end if;
  if not (p_emoji = any(public.wish_emojis())) then raise exception 'Tokios reakcijos nėra'; end if;
  if not exists (select 1 from public.wishes where id = p_wish and board_id = b.id and status = 'approved') then raise exception 'Linkėjimas nerastas'; end if;
  if exists (select 1 from public.wish_reactions where wish_id = p_wish and voter = v and emoji = p_emoji) then
    delete from public.wish_reactions where wish_id = p_wish and voter = v and emoji = p_emoji;
  else
    if (select count(*) from public.wish_reactions r join public.wishes w on w.id = r.wish_id where w.board_id = b.id and r.voter = v and r.created_at > now() - interval '10 minutes') >= 300 then
      raise exception 'Per daug reakcijų – pabandyk po kelių minučių'; end if;
    insert into public.wish_reactions (wish_id, voter, emoji) values (p_wish, v, p_emoji);
  end if;
  return jsonb_build_object('counts', public.wish_rcounts(p_wish),
    'mine', coalesce((select jsonb_agg(emoji) from public.wish_reactions where wish_id = p_wish and voter = v), '[]'::jsonb));
end $$;
revoke all on function public.wish_react(text, uuid, text, text) from public;
grant execute on function public.wish_react(text, uuid, text, text) to anon, authenticated;

-- the control page (wishes_mod2.sql) – board_update also takes reactions; list gives each wish's emoji counts
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
    if coalesce(a->>'status', '') not in ('new','approved','hidden') then raise exception 'Neteisinga būsena'; end if;
    if a->>'status' = 'approved' then
      select coalesce(max(sort), 0) + 1 into v_sort from public.wishes where board_id = (select board_id from public.wishes where id = v_id) and status = 'approved';
      update public.wishes set status = 'approved', approved_at = now(), sort = v_sort where id = v_id;
    else update public.wishes set status = a->>'status' where id = v_id; end if;
    return jsonb_build_object('ok', true);
  elsif p_action = 'wish_sort' then
    update public.wishes set sort = (a->>'sort')::double precision where id = v_id; return jsonb_build_object('ok', true);
  elsif p_action = 'wish_delete' then
    delete from public.wishes where id = v_id; return jsonb_build_object('ok', true);
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

-- the QR page (wishes_mod2.sql) – also says whether emoji reactions are on
create or replace function public.wish_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare b public.wish_boards;
begin
  if not public.poll_enabled() then return jsonb_build_object('off', true); end if;
  select * into b from public.wish_boards where submit_token = p_token;
  if b.id is null then return null; end if;
  return jsonb_build_object('name', b.name, 'open', b.open, 'brand', b.brand, 'reactions', b.reactions,
    'banned', to_jsonb((case when b.filter and b.swear then public.wish_bad_builtin() else '{}'::text[] end) || (case when b.filter then coalesce(b.banned, '{}') else '{}'::text[] end)));
end $$;
revoke all on function public.wish_public(text) from public;
grant execute on function public.wish_public(text) to anon, authenticated;
notify pgrst, 'reload schema';
