-- ============================================================
-- Balsavimai, 5 dalis (paleisti po polls.sql … polls4.sql):
--  * keli BALSAVIMAI su pavadinimais (poll_sets). Kiekvienas turi savo
--    klausimus, apipavidalinimą, nuolatinį QR kodą ir rezultatų nuorodą.
--    Esami klausimai ir QR kodas perkeliami į pirmą balsavimą
--    „Balsavimas“ (atsisiųstas QR kodas toliau veikia).
--  * klausimui – vienas arba keli pasirinkimai (polls.multi)
--  * rezultatų ekranas: tik nugalėtojas (arba visi atsakymai – show_all)
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- (Funkcijose nenaudojama „select … into“ – Supabase SQL Editor ją klaidingai
--  palaiko nauja lentele ir sugadina užklausą.)
-- ============================================================

create table if not exists public.poll_sets (
  id            uuid primary key default gen_random_uuid(),
  name          text not null default 'Balsavimas' check (char_length(name) <= 200),
  vote_token    text not null unique default (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  results_token text not null unique default (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  brand         jsonb not null default '{}'::jsonb,
  results_w     int not null default 1920 check (results_w between 100 and 8000),
  results_h     int not null default 1080 check (results_h between 100 and 8000),
  show_all      boolean not null default false,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
alter table public.poll_sets enable row level security;
revoke all on public.poll_sets from anon, authenticated;

alter table public.polls add column if not exists set_id uuid references public.poll_sets(id) on delete cascade;
alter table public.polls add column if not exists multi boolean not null default false;
create index if not exists polls_set on public.polls (set_id);

-- the questions and the permanent QR so far become the first voting
do $$
declare v uuid := gen_random_uuid();
begin
  if not exists (select 1 from public.poll_sets) then
    insert into public.poll_sets (id, name, vote_token, results_token, brand, results_w, results_h)
      select v, 'Balsavimas',
             coalesce(max(st.vote_token), replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
             coalesce(max(st.results_token), replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
             coalesce((array_agg(st.brand))[1], '{}'::jsonb), coalesce(max(st.results_w), 1920), coalesce(max(st.results_h), 1080)
        from public.poll_settings st where st.id = 1;
    update public.polls set set_id = v where set_id is null;
  end if;
  update public.polls set set_id = (select id from public.poll_sets order by created_at limit 1) where set_id is null;
end $$;

-- several choices: one row per chosen answer (one submission per phone)
alter table public.poll_votes drop constraint if exists poll_votes_poll_id_round_voter_key;
create unique index if not exists poll_votes_one_option on public.poll_votes (poll_id, round, voter, option_id);
create index if not exists poll_votes_voter on public.poll_votes (poll_id, round, voter);

-- which question a voting's links show: the running one, else the next to start
create or replace function public.poll_set_current(p_set uuid) returns public.polls
  language sql stable security definer set search_path = public as $$
  select * from (
    (select * from public.polls where set_id = p_set and starts_at <= now() and ends_at > now() order by starts_at desc limit 1)
    union all
    (select * from public.polls where set_id = p_set and starts_at > now() order by starts_at asc limit 1)
  ) x limit 1
$$;
revoke all on function public.poll_set_current(uuid) from public, anon, authenticated;

-- one question at a time in a voting: starting one stops the others there
create or replace function public.poll_do_start(p_id uuid, p_delay int) returns public.polls
  language plpgsql security definer set search_path = public as $$
declare p public.polls; t timestamptz := now() + make_interval(secs => greatest(0, least(coalesce(p_delay, 0), 86400)));
begin
  update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
    where id <> p_id and ends_at > now() and set_id is not distinct from (select set_id from public.polls where id = p_id);
  update public.polls set round = round + 1, starts_at = t, ends_at = t + make_interval(secs => duration_sec), updated_at = now()
    where id = p_id;
  p := (select x from public.polls x where x.id = p_id);
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return p;
end $$;
revoke all on function public.poll_do_start(uuid, int) from public, anon, authenticated;

create or replace function public.poll_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; st text; s public.poll_sets;
begin
  s := (select x from public.poll_sets x where x.vote_token = p_token);
  if s.id is not null then p := public.poll_set_current(s.id);
  else p := (select x from public.polls x where x.vote_token = p_token);
       if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if; end if;
  if p.id is null then return jsonb_build_object('state', case when s.id is not null then 'idle' else 'invalid' end, 'now', now(), 'brand', coalesce(s.brand, '{}'::jsonb)); end if;
  st := public.poll_state(p);
  if s.id is not null and p_token = s.vote_token and st not in ('waiting', 'live') then st := 'idle'; end if;
  return jsonb_build_object('state', st, 'now', now(), 'poll', p.id, 'round', p.round, 'starts_at', p.starts_at, 'ends_at', p.ends_at,
    'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'topic', case when st in ('waiting', 'live') then nullif(p.topic, '') end,
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;

-- a vote: one or several answers (several only when the question allows it)
create or replace function public.poll_vote_many(p_token text, p_options text[], p_voter text, p_poll uuid) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; opts text[];
begin
  s := (select x from public.poll_sets x where x.vote_token = p_token);
  if s.id is not null then p := (select x from public.polls x where x.id = p_poll and x.set_id = s.id);
  else p := (select x from public.polls x where x.vote_token = p_token); end if;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if coalesce(length(p_voter), 0) not between 8 and 100 then return 'bad'; end if;
  opts := (select array_agg(distinct o) from unnest(coalesce(p_options, '{}'::text[])) o);
  if coalesce(array_length(opts, 1), 0) = 0 or (not p.multi and array_length(opts, 1) > 1) then return 'bad'; end if;
  if exists (select 1 from unnest(opts) x where not exists (select 1 from jsonb_array_elements(p.options) o where o->>'id' = x)) then return 'bad'; end if;
  perform pg_advisory_xact_lock(hashtext(p.id::text || ':' || p_voter));
  if exists (select 1 from public.poll_votes where poll_id = p.id and round = p.round and voter = p_voter) then return 'already'; end if;
  insert into public.poll_votes (poll_id, round, option_id, voter) select p.id, p.round, x, p_voter from unnest(opts) x;
  return 'ok';
end $$;
revoke all on function public.poll_vote_many(text, text[], text, uuid) from public;
grant execute on function public.poll_vote_many(text, text[], text, uuid) to anon, authenticated;

create or replace function public.poll_vote(p_token text, p_option text, p_voter text, p_poll uuid) returns text
  language sql security definer set search_path = public as $$
  select public.poll_vote_many(p_token, array[p_option], p_voter, p_poll)
$$;
create or replace function public.poll_vote(p_token text, p_option text, p_voter text) returns text
  language sql security definer set search_path = public as $$
  select public.poll_vote_many(p_token, array[p_option], p_voter, null)
$$;
revoke all on function public.poll_vote(text, text, text, uuid), public.poll_vote(text, text, text) from public;
grant execute on function public.poll_vote(text, text, text, uuid), public.poll_vote(text, text, text) to anon, authenticated;

-- results: 'total' = people who voted; each answer's votes (several answers → more than 100 % together)
create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  s := (select x from public.poll_sets x where x.results_token = p_token);
  if s.id is not null then
    perm := true;
    p := public.poll_set_current(s.id);
    if p.id is null then p := (select x from public.polls x where x.set_id = s.id and x.ends_at <= now() order by x.ends_at desc limit 1); end if;
  else
    p := (select x from public.polls x where x.results_token = p_token);
    if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
grant execute on function public.poll_public(text), public.poll_results(text) to anon, authenticated;

-- the editor (admin, or anyone with the editor link)
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; s public.poll_sets; v_id uuid; v_new uuid; v_set uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  -- votings
  if p_action = 'sets' then
    return coalesce((select jsonb_agg(to_jsonb(x) || jsonb_build_object(
              'questions', (select count(*) from public.polls q where q.set_id = x.id),
              'live', (select count(*) from public.polls q where q.set_id = x.id and q.ends_at > now()))
            order by x.created_at desc) from public.poll_sets x), '[]'::jsonb);
  elsif p_action = 'set_create' then
    v_new := gen_random_uuid();
    insert into public.poll_sets (id, name) values (v_new, left(coalesce(nullif(trim(a->>'name'), ''), 'Balsavimas'), 200));
    return (select to_jsonb(x) from public.poll_sets x where x.id = v_new);
  elsif p_action = 'set_update' then
    update public.poll_sets set
        name = left(coalesce(nullif(trim(a->>'name'), ''), name), 200), brand = coalesce(a->'brand', brand),
        results_w = greatest(100, least(8000, coalesce((a->>'results_w')::int, results_w))),
        results_h = greatest(100, least(8000, coalesce((a->>'results_h')::int, results_h))),
        show_all = coalesce((a->>'show_all')::boolean, show_all), updated_at = now()
      where id = (a->>'id')::uuid;
    s := (select x from public.poll_sets x where x.id = (a->>'id')::uuid);
    if s.id is null then raise exception 'Balsavimas nerastas'; end if;
    return to_jsonb(s);
  elsif p_action = 'set_delete' then
    delete from public.poll_sets where id = (a->>'id')::uuid;
    return '{}'::jsonb;
  -- questions of one voting
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x where x.set_id = (a->>'set')::uuid), '[]'::jsonb);
  elsif p_action = 'create' then
    v_set := (a->>'set')::uuid;
    if not exists (select 1 from public.poll_sets where id = v_set) then raise exception 'Balsavimas nerastas'; end if;
    v_new := gen_random_uuid();
    insert into public.polls (id, set_id, topic, question, options, duration_sec, multi, sort, created_by)
      values (v_new, v_set, left(coalesce(a->>'topic', ''), 200), left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb),
              coalesce((a->>'duration_sec')::int, 60), coalesce((a->>'multi')::boolean, false),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls where set_id = v_set)), auth.uid());
    return (select to_jsonb(x) from public.polls x where x.id = v_new);
  elsif p_action = 'upload' then
    if coalesce(a->>'mime', '') !~ '^(image/(png|jpeg|webp|gif)|font/(ttf|otf|woff2?|sfnt)|application/(font-woff2?|x-font-(ttf|otf)|vnd\.ms-opentype|octet-stream))$' then
      raise exception 'Netinkamas failo tipas'; end if;
    if length(coalesce(a->>'data', '')) > 12000000 then raise exception 'Failas per didelis'; end if;
    v_new := gen_random_uuid();
    insert into public.poll_assets (id, mime, data, bytes) values (v_new, a->>'mime', a->>'data', length(a->>'data') * 3 / 4);
    return jsonb_build_object('id', v_new);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'update' then
    update public.polls set
        topic = left(coalesce(a->>'topic', topic), 200), question = left(coalesce(a->>'question', question), 500),
        options = coalesce(a->'options', options), duration_sec = coalesce((a->>'duration_sec')::int, duration_sec),
        multi = coalesce((a->>'multi')::boolean, multi), sort = coalesce((a->>'sort')::int, sort), updated_at = now()
      where id = v_id;
    p := (select x from public.polls x where x.id = v_id);
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
