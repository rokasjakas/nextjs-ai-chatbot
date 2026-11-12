-- ============================================================
-- Balsavimai, 3 dalis (paleisti po polls.sql ir polls2.sql):
--  * apipavidalinimas ir rezultatų ekrano dydis – bendri VISIEMS klausimams
--    (seniems ir naujiems), saugomi poll_settings. Pirmą kartą paimamas
--    paskutinio redaguoto klausimo apipavidalinimas.
--  * VIENAS nuolatinis QR kodas (?balsuoti=<raktas>) ir viena rezultatų
--    nuoroda visiems klausimams – niekada nesikeičia. Rodomas tuo metu
--    vykstantis klausimas; jei nevyksta nė vienas – tik fonas ir logotipas.
--  * paleidus klausimą, kitas tuo metu vykstantis sustabdomas
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.poll_settings add column if not exists brand jsonb;
alter table public.poll_settings add column if not exists results_w int;
alter table public.poll_settings add column if not exists results_h int;

insert into public.poll_settings (id) values (1) on conflict (id) do nothing;
update public.poll_settings s set
    brand = coalesce(s.brand, (select p.brand from public.polls p where p.brand <> '{}'::jsonb order by p.updated_at desc limit 1), '{}'::jsonb),
    results_w = coalesce(s.results_w, (select p.results_w from public.polls p order by p.updated_at desc limit 1), 1920),
    results_h = coalesce(s.results_h, (select p.results_h from public.polls p order by p.updated_at desc limit 1), 1080)
  where s.id = 1;

-- the shared look (for the pages)
create or replace function public.poll_look() returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('brand', coalesce(brand, '{}'::jsonb), 'w', coalesce(results_w, 1920), 'h', coalesce(results_h, 1080))
    from public.poll_settings where id = 1
$$;
revoke all on function public.poll_look() from public, anon, authenticated;

create or replace function public.poll_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; st text; lk jsonb := coalesce(public.poll_look(), '{}'::jsonb);
begin
  select * into p from public.polls where vote_token = p_token;
  if p.id is null then return jsonb_build_object('state', 'invalid', 'now', now(), 'brand', lk->'brand'); end if;
  st := public.poll_state(p);
  return jsonb_build_object('state', st, 'now', now(), 'round', p.round, 'starts_at', p.starts_at, 'ends_at', p.ends_at,
    'brand', coalesce(lk->'brand', p.brand),
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; lk jsonb := coalesce(public.poll_look(), '{}'::jsonb);
begin
  select * into p from public.polls where results_token = p_token;
  if p.id is null then return jsonb_build_object('state', 'invalid'); end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'round', p.round, 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(lk->'brand', p.brand),
    'w', coalesce((lk->>'w')::int, p.results_w), 'h', coalesce((lk->>'h')::int, p.results_h),
    'total', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
grant execute on function public.poll_public(text), public.poll_results(text) to anon, authenticated;

-- the editor: + 'look' (read) and 'set_look' (save) for the shared look
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; v_id uuid; v_new uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  if p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x), '[]'::jsonb);
  elsif p_action = 'look' then
    return public.poll_look();
  elsif p_action = 'set_look' then
    insert into public.poll_settings (id) values (1) on conflict (id) do nothing;
    update public.poll_settings set
        brand = coalesce(a->'brand', brand),
        results_w = greatest(100, least(8000, coalesce((a->>'results_w')::int, results_w, 1920))),
        results_h = greatest(100, least(8000, coalesce((a->>'results_h')::int, results_h, 1080))),
        updated_at = now()
      where id = 1;
    return public.poll_look();
  elsif p_action = 'create' then
    insert into public.polls (question, options, duration_sec, sort, created_by)
      values (left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb), coalesce((a->>'duration_sec')::int, 60),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls)), auth.uid())
      returning * into p;
    return to_jsonb(p);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    insert into public.poll_assets (mime, data, bytes) values (a->>'mime', a->>'data', length(a->>'data') * 3 / 4) returning id into v_new;
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        question = left(coalesce(a->>'question', question), 500), options = coalesce(a->'options', options),
        duration_sec = coalesce((a->>'duration_sec')::int, duration_sec),
        sort = coalesce((a->>'sort')::int, sort), updated_at = now()
      where id = v_id returning * into p;
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'stop' then
    p := public.poll_do_stop(v_id);
  else
    raise exception 'Nežinomas veiksmas';
  end if;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return to_jsonb(p);
end $$;
revoke all on function public.poll_admin(text, text, jsonb) from public;
grant execute on function public.poll_admin(text, text, jsonb) to anon, authenticated;


-- ---------- vienas nuolatinis QR kodas ir rezultatų nuoroda ----------
alter table public.poll_settings add column if not exists vote_token text;
alter table public.poll_settings add column if not exists results_token text;
update public.poll_settings set
    vote_token = coalesce(vote_token, replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
    results_token = coalesce(results_token, replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''))
  where id = 1;

create or replace function public.poll_look() returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('brand', coalesce(brand, '{}'::jsonb), 'w', coalesce(results_w, 1920), 'h', coalesce(results_h, 1080),
                            'vote_token', vote_token, 'results_token', results_token)
    from public.poll_settings where id = 1
$$;
revoke all on function public.poll_look() from public, anon, authenticated;

-- which question the permanent links show: the running one, else the next to start
create or replace function public.poll_current() returns public.polls
  language sql stable security definer set search_path = public as $$
  select * from (
    (select * from public.polls where starts_at <= now() and ends_at > now() order by starts_at desc limit 1)
    union all
    (select * from public.polls where starts_at > now() order by starts_at asc limit 1)
  ) x limit 1
$$;
revoke all on function public.poll_current() from public, anon, authenticated;

-- one question at a time: starting one stops the others
create or replace function public.poll_do_start(p_id uuid, p_delay int) returns public.polls
  language plpgsql security definer set search_path = public as $$
declare p public.polls; t timestamptz := now() + make_interval(secs => greatest(0, least(coalesce(p_delay, 0), 86400)));
begin
  update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
    where id <> p_id and ends_at > now();
  update public.polls set round = round + 1, starts_at = t, ends_at = t + make_interval(secs => duration_sec), updated_at = now()
    where id = p_id returning * into p;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return p;
end $$;
revoke all on function public.poll_do_start(uuid, int) from public, anon, authenticated;

create or replace function public.poll_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; st text; lk jsonb := coalesce(public.poll_look(), '{}'::jsonb); perm boolean := p_token is not null and p_token = lk->>'vote_token';
begin
  if perm then p := public.poll_current();
  else select * into p from public.polls where vote_token = p_token; end if;
  if p.id is null then return jsonb_build_object('state', case when perm then 'idle' else 'invalid' end, 'now', now(), 'brand', lk->'brand'); end if;
  st := public.poll_state(p);
  if perm and st not in ('waiting', 'live') then st := 'idle'; end if;
  return jsonb_build_object('state', st, 'now', now(), 'poll', p.id, 'round', p.round, 'starts_at', p.starts_at, 'ends_at', p.ends_at,
    'brand', coalesce(lk->'brand', p.brand),
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;

-- a vote through the permanent QR names the question it was cast for
create or replace function public.poll_vote(p_token text, p_option text, p_voter text, p_poll uuid) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls; lk jsonb := coalesce(public.poll_look(), '{}'::jsonb);
begin
  if p_token is not null and p_token = lk->>'vote_token' then select * into p from public.polls where id = p_poll;
  else select * into p from public.polls where vote_token = p_token; end if;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if coalesce(length(p_voter), 0) not between 8 and 100 then return 'bad'; end if;
  if not exists (select 1 from jsonb_array_elements(p.options) o where o->>'id' = p_option) then return 'bad'; end if;
  insert into public.poll_votes (poll_id, round, option_id, voter) values (p.id, p.round, p_option, p_voter)
    on conflict (poll_id, round, voter) do nothing;
  if not found then return 'already'; end if;
  return 'ok';
end $$;
revoke all on function public.poll_vote(text, text, text, uuid) from public;
grant execute on function public.poll_vote(text, text, text, uuid) to anon, authenticated;

-- the permanent results link: the running question, else the last one that ended
create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; lk jsonb := coalesce(public.poll_look(), '{}'::jsonb); perm boolean := p_token is not null and p_token = lk->>'results_token';
begin
  if perm then
    p := public.poll_current();
    if p.id is null then select * into p from public.polls where ends_at <= now() order by ends_at desc limit 1; end if;
  else select * into p from public.polls where results_token = p_token; end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', lk->'brand', 'w', (lk->>'w')::int, 'h', (lk->>'h')::int)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(lk->'brand', p.brand),
    'w', coalesce((lk->>'w')::int, p.results_w), 'h', coalesce((lk->>'h')::int, p.results_h),
    'total', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
grant execute on function public.poll_public(text), public.poll_results(text) to anon, authenticated;
