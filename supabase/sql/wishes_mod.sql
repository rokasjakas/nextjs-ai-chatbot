-- ============================================================
-- wishes_mod.sql — Linkėjimai: žodžių moderavimas
--  * keiksmažodžių filtras (įjungtas pagal nutylėjimą; galima išjungti kiekvienai linkėjimų lentai)
--  * savas draudžiamų žodžių sąrašas kiekvienai lentai („žodis“ – tik visas žodis, „žodis*“ – visi žodžiai, prasidedantys juo)
--  * tikrinama serveryje (wish_submit): rašant ir linkėjimą, ir vardą; tikrinant nepaisoma didžiųjų raidžių, lietuviškų
--    raidžių (š = s), pasikartojančių raidžių (kuuurva), skaičių vietoj raidžių (sh1t) ir tarpų tarp raidžių (f u c k)
-- Reikia: wishes.sql. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.wish_boards add column if not exists filter boolean not null default true;
alter table public.wish_boards add column if not exists banned text[] not null default '{}';

-- a text made comparable: lower case, no Lithuanian marks, y = i, digits and signs read as letters,
-- no repeated letters, words separated by one space (with a space at both ends)
create or replace function public.wish_norm(p text) returns text language sql immutable as $$
  select ' ' || trim(regexp_replace(regexp_replace(
    translate(lower(coalesce(p, '')), 'ąčęėįšųūžy013457@$8', 'aceeisuuzioieastasb'),
    '[^a-z]+', ' ', 'g'), '([a-z])\1+', '\1', 'g')) || ' ';
$$;
-- the same, with letters written apart joined (f u c k → fuck)
create or replace function public.wish_norm_join(p text) returns text language plpgsql immutable as $$
declare w text; o text := ''; run text := '';
begin
  foreach w in array regexp_split_to_array(trim(public.wish_norm(p)), ' ') loop
    if length(w) = 1 then run := run || w;
    else
      if run <> '' then o := o || ' ' || run; run := ''; end if;
      if w <> '' then o := o || ' ' || w; end if;
    end if;
  end loop;
  if run <> '' then o := o || ' ' || run; end if;
  return o || ' ';
end $$;

-- the built-in list: whole words, and stems with * (every word beginning with it)
create or replace function public.wish_bad_builtin() returns text[] language sql immutable as $$
  select array[
    -- lietuvių / rusų kalba (rašoma lotyniškai)
    'pizd*','pyzd*','pizdec','kurv*','chuj*','chui','huj*','nachui','nachuj','nahui','nahuj','naxui','naxuj','nx',
    'blet','bliat','bliad','blyat','blya','blia','blat','blet*','bliat*','bliad*',
    'pidar*','pyder*','pider*','pydar*','pederast*',
    'sudas','sudo','sude','sudu','sudai','sudus','sudina','sudinas','sudzius','sudzi*',
    'sikn*','sikti','sikt','sika','sikis','siku','sikna','sikinas','prisikt*','apsikt*','apsisikt*',
    'pisti','pisk','pisu','pisa','pisasi','pisimas','pistis','pisa','pisk*','papisti','isipisti','nusipisk*','pisdavo','pisam',
    'jobt*','jobn*','joban*','jeban*','jebat*','ebat*','zajeb*','pojeb*','dolbojob*','dalbajob*','dolbajob*','debil*','mudak*','gandon*','zalup*','suka','suki','suke','sukos','sukute',
    'myzal*','mizal*','mudil*',
    -- anglų kalba
    'fuck*','fck','fcking','fuk*','motherfuck*','shit','shits','shitty','shitting','shithead*','bullshit*','bitch*','cunt*','asshole*','ashole*','bastard*','whore*','slut*','dick','dicks','dickhead*','pussy','wank*','twat*','cock','cocks','cocksuck*'
  ];
$$;

-- does the text hold a word not allowed: the built-in list (when p_filter) and the board's own list
create or replace function public.wish_bad_hit(p_text text, p_filter boolean, p_banned text[]) returns boolean
  language plpgsql immutable as $$
declare t1 text := public.wish_norm(p_text); t2 text := public.wish_norm_join(p_text); e text; w text; pre boolean;
begin
  foreach e in array (case when p_filter then public.wish_bad_builtin() else '{}'::text[] end) || coalesce(p_banned, '{}') loop
    pre := right(trim(e), 1) = '*';
    w := trim(public.wish_norm(rtrim(trim(e), '*')));
    if w = '' then continue; end if;
    if pre then
      if position(' ' || w in t1) > 0 or position(' ' || w in t2) > 0 then return true; end if;
    else
      if position(' ' || w || ' ' in t1) > 0 or position(' ' || w || ' ' in t2) > 0 then return true; end if;
    end if;
  end loop;
  return false;
end $$;
revoke all on function public.wish_bad_hit(text, boolean, text[]) from public;

-- the control page (wishes.sql) – board_update now also takes filter and banned
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
      banned = case when a ? 'banned' then coalesce((select array_agg(distinct x) from (select left(lower(trim(e)), 60) x from jsonb_array_elements_text(a->'banned') e) q where x <> ''), '{}') else banned end
    where id = v_id returning * into b;
    return to_jsonb(b);
  elsif p_action = 'board_delete' then
    delete from public.wish_boards where id = v_id; return jsonb_build_object('ok', true);
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(w) - 'voter' order by coalesce(w.sort, extract(epoch from w.created_at)), w.created_at)
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

-- a wish written on a phone (wishes.sql) – now also checked for words not allowed
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
  if p_voter is not null and (select count(*) from public.wishes where board_id = b.id and voter = p_voter and created_at > now() - interval '10 minutes') >= 6 then
    raise exception 'Per daug linkėjimų iš karto – pabandyk po kelių minučių'; end if;
  if public.wish_bad_hit(t || ' ' || coalesce(n, ''), b.filter, b.banned) then
    raise exception 'Linkėjime yra neleistinų žodžių – pataisyk ir siųsk dar kartą'; end if;
  if (select count(*) from public.wishes where board_id = b.id and status = 'new') >= 3000 then raise exception 'Linkėjimų per daug'; end if;
  insert into public.wishes (board_id, text, name, voter) values (b.id, t, left(n, 80), left(p_voter, 40));
  return jsonb_build_object('ok', true);
end $$;
revoke all on function public.wish_submit(text, text, text, text) from public;
grant execute on function public.wish_submit(text, text, text, text) to anon, authenticated;
-- the QR page (wishes.sql) – now also gives the words not allowed, so the phone takes them out while typing
create or replace function public.wish_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare b public.wish_boards;
begin
  if not public.poll_enabled() then return jsonb_build_object('off', true); end if;
  select * into b from public.wish_boards where submit_token = p_token;
  if b.id is null then return null; end if;
  return jsonb_build_object('name', b.name, 'open', b.open, 'brand', b.brand,
    'banned', to_jsonb((case when b.filter then public.wish_bad_builtin() else '{}'::text[] end) || coalesce(b.banned, '{}')));
end $$;
revoke all on function public.wish_public(text) from public;
grant execute on function public.wish_public(text) to anon, authenticated;
notify pgrst, 'reload schema';
