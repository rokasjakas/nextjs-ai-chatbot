-- ============================================================
-- Balsavimai, 15 dalis (paleisti po polls14.sql): KELIOS TEMOS – ĮRAŠO PATYS
--  * nominacijos tipas „Kelios temos“ (polls.kind = 'multi'): telefone
--    visos temos, kiekvienai įrašomas vardas ir pavardė (tas pats vardas
--    gali būti keliose temose); balsuoti – tik užpildžius visas temas
--  * pasibaigus laikui – „Balsavimas baigėsi“; kiekvienos temos laimėtojas
--    (daugiausiai kartų įrašytas vardas) rodomas atskiru mygtuku
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

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
    'brand', coalesce(s.brand, p.brand), 'multi', p.multi, 'write', p.kind = 'write', 'write_max', p.write_max, 'mw', p.kind = 'multi',
    'topic', case when st in ('waiting', 'live') then nullif(p.topic, '') end,
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' and p.kind <> 'write' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;
grant execute on function public.poll_public(text) to anon, authenticated;

create or replace function public.poll_vote_many(p_token text, p_options text[], p_voter text, p_poll uuid) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; opts text[];
begin
  s := (select x from public.poll_sets x where x.vote_token = p_token);
  if s.id is not null then p := (select x from public.polls x where x.id = p_poll and x.set_id = s.id);
  else p := (select x from public.polls x where x.vote_token = p_token); end if;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if coalesce(length(p_voter), 0) not between 8 and 100 or p.kind <> 'question' then return 'bad'; end if;
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

-- several topics: one name per topic, all topics filled, one submission per phone; the same name may be in
-- different topics; within a topic a name near one already written counts for it
create or replace function public.poll_mwrite(p_token text, p_topics text[], p_names text[], p_voter text, p_poll uuid) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; i int; tid text; t text; nm text; k text; ks text[] := '{}'; es text[] := '{}'; tn int;
begin
  s := (select x from public.poll_sets x where x.vote_token = p_token);
  if s.id is not null then p := (select x from public.polls x where x.id = p_poll and x.set_id = s.id);
  else p := (select x from public.polls x where x.vote_token = p_token); end if;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if p.kind <> 'multi' or coalesce(length(p_voter), 0) not between 8 and 100 then return 'bad'; end if;
  tn := jsonb_array_length(p.options);
  if tn = 0 or coalesce(array_length(p_topics, 1), 0) <> tn or coalesce(array_length(p_names, 1), 0) <> tn then return 'bad'; end if;
  if (select count(distinct x) from unnest(p_topics) x where exists (select 1 from jsonb_array_elements(p.options) o where o->>'id' = x)) <> tn then return 'bad'; end if;
  perform pg_advisory_xact_lock(hashtext('poll_write:' || p.id::text));
  if exists (select 1 from public.poll_votes where poll_id = p.id and round = p.round and voter = p_voter) then return 'already'; end if;
  for i in 1..tn loop
    tid := p_topics[i];
    t := left(regexp_replace(btrim(coalesce(p_names[i], '')), '\s+', ' ', 'g'), 80);
    nm := public.poll_name_norm(t);
    if nm = '' then return 'bad'; end if;
    k := (select z.k from (select v.option_id k, count(*) c from public.poll_votes v
                             where v.poll_id = p.id and v.round = p.round and v.option_id like tid || ':%' group by v.option_id) z
           where public.poll_name_near(nm, public.poll_name_norm(substr(z.k, length(tid) + 4))) order by z.c desc, z.k limit 1);
    ks := ks || coalesce(k, tid || ':w:' || nm); es := es || t;
  end loop;
  insert into public.poll_votes (poll_id, round, option_id, voter, entry) select p.id, p.round, ks[j], p_voter, es[j] from generate_subscripts(ks, 1) j;
  return 'ok';
end $$;
revoke all on function public.poll_mwrite(text, text[], text[], text, uuid) from public;
grant execute on function public.poll_mwrite(text, text[], text[], text, uuid) to anon, authenticated;

create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; perm boolean := false;
begin
  s := (select x from public.poll_sets x where x.results_token = p_token);
  if s.id is not null then
    perm := true;
    -- nominees / the winner chosen beforehand
    if s.display is not null then
      p := (select x from public.polls x where x.id = (s.display->>'poll')::uuid and x.set_id = s.id);
      if p.id is not null and s.display->>'mode' = 'nomination' then
        return jsonb_build_object('state', 'nomination', 'now', now(), 'poll', p.id, 'round', p.round, 'at', s.display->>'at',
          'topic', nullif(p.topic, ''), 'question', p.question, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          -- a winner marked 🏆 beforehand means no voting: then no QR code
          'vote_token', case when not exists (select 1 from jsonb_array_elements(p.options) o where o->>'winner' = 'true') then s.vote_token end);
      end if;
      if p.id is not null and s.display->>'mode' = 'splash' then
        return jsonb_build_object('state', 'splash', 'now', now(), 'poll', p.id, 'at', s.display->>'at', 'topic', nullif(p.topic, ''),
          'splash', p.brand, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all);
      end if;
      if p.id is not null then
        return jsonb_build_object('state', case when s.display->>'mode' = 'winner' then 'reveal' else 'nominees' end, 'now', now(),
          'poll', p.id, 'round', p.round, 'at', s.display->>'at', 'topic', nullif(p.topic, ''), 'question', p.question,
          'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          'options', case when p.kind = 'multi' then
                        -- several topics: each topic (or only the one chosen) with its most written name(s)
                        (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text', 'winner', s.display->>'mode' = 'winner',
                           'names', case when s.display->>'mode' = 'winner' then (select coalesce(jsonb_agg(z.t order by z.t), '[]'::jsonb) from (
                              select count(*) c, max(count(*)) over () m, (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                                from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id like (o->>'id') || ':%' group by v.option_id) z where z.c = z.m)
                             else '[]'::jsonb end) order by x.n), '[]'::jsonb)
                         from jsonb_array_elements(p.options) with ordinality as x(o, n)
                         where coalesce(s.display->>'topic', '') = '' or o->>'id' = s.display->>'topic')
                      when p.kind = 'write' then
                        -- typed names: the most written one(s) win, shown only now
                        (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'winner', s.display->>'mode' = 'winner' and z.n = z.m) order by z.n desc, z.t), '[]'::jsonb) from (
                           select v.option_id k, count(*) n, max(count(*)) over () m,
                                  (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                                     group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                             from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                             group by v.option_id order by count(*) desc, v.option_id limit 15) z)
                      -- nominees: the most voted one(s) win; with no votes – the one marked 🏆 beforehand
                      else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                        'winner', s.display->>'mode' = 'winner' and case when vm.m > 0 then vc.cnt = vm.m else coalesce(o->>'winner', '') = 'true' end) order by x.n), '[]'::jsonb)
                      from jsonb_array_elements(p.options) with ordinality as x(o, n)
                      cross join lateral (select count(*) cnt from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = x.o->>'id') vc
                      cross join (select coalesce(max(q.c), 0) m from (select count(*) c from public.poll_votes v where v.poll_id = p.id and v.round = p.round group by v.option_id) q) vm) end);
      end if;
    end if;
    p := public.poll_set_current(s.id);
    if p.id is null then p := (select x from public.polls x where x.set_id = s.id and x.ends_at <= now() order by x.ends_at desc limit 1); end if;
  else
    p := (select x from public.polls x where x.results_token = p_token);
    if p.id is not null then s := (select x from public.poll_sets x where x.id = p.set_id); end if;
  end if;
  if p.id is null then
    return case when perm then jsonb_build_object('state', 'idle', 'now', now(), 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token)
                else jsonb_build_object('state', 'invalid') end;
  end if;
  -- on the voting's screen: when the time is up only "voting ended" – the winner waits for the editor's button
  if perm and public.poll_state(p) = 'ended' then
    return jsonb_build_object('state', 'ended', 'hold', true, 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
      'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', s.brand, 'multi', p.multi, 'write', p.kind = 'write', 'mw', p.kind = 'multi',
      'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token, 'total', 0, 'options', '[]'::jsonb);
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'vote_token', case when perm then s.vote_token end,
    'write', p.kind = 'write',
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'mw', p.kind = 'multi',
    'options', case when p.kind = 'multi' then
                 -- several topics: per topic the entries and the 5 most written names
                 (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                    'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id like (o->>'id') || ':%'),
                    'top', (select coalesce(jsonb_agg(jsonb_build_object('text', z.t, 'votes', z.c) order by z.c desc, z.t), '[]'::jsonb) from (
                       select count(*) c, (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                         from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id like (o->>'id') || ':%'
                         group by v.option_id order by count(*) desc, v.option_id limit 5) z)) order by x.n), '[]'::jsonb)
                  from jsonb_array_elements(p.options) with ordinality as x(o, n))
               when p.kind = 'write' then
                 -- names typed by the voters: the same name (letter case and spaces aside) counts together,
                 -- shown as it was typed most often; the 15 most written
                 (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'votes', z.n) order by z.n desc, z.t), '[]'::jsonb) from (
                    select v.option_id k, count(*) n,
                           (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                              group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                      from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                      group by v.option_id order by count(*) desc, v.option_id limit 15) z)
               else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
end $$;
grant execute on function public.poll_results(text) to anon, authenticated;

-- the editor (admin, or anyone with the editor link)
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; s public.poll_sets; v_id uuid; v_new uuid; v_set uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  -- votings
  if p_action = 'sets' then
    return coalesce((select jsonb_agg(to_jsonb(x) || jsonb_build_object(
              'questions', (select count(*) from public.polls q where q.set_id = x.id and q.kind <> 'splash'),
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
  elsif p_action = 'set_get' then
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'id')::uuid);
  elsif p_action = 'hide' then
    update public.poll_sets set display = null, updated_at = now() where id = (a->>'set')::uuid;
    return (select to_jsonb(x) from public.poll_sets x where x.id = (a->>'set')::uuid);
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
    insert into public.polls (id, set_id, kind, brand, topic, question, options, duration_sec, multi, sort, created_by)
      values (v_new, v_set, case when a->>'kind' in ('splash', 'write', 'multi') then a->>'kind' else 'question' end, coalesce(a->'brand', '{}'::jsonb),
              left(coalesce(a->>'topic', ''), 200), left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb),
              coalesce((a->>'duration_sec')::int, 60), coalesce((a->>'multi')::boolean, false),
              coalesce((a->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.polls where set_id = v_set)), auth.uid());
    update public.polls set write_max = greatest(1, least(50, coalesce((a->>'write_max')::int, 1))) where id = v_new;
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
        multi = coalesce((a->>'multi')::boolean, multi), sort = coalesce((a->>'sort')::int, sort),
        brand = case when kind = 'splash' then coalesce(a->'brand', brand) else brand end,
        kind = case when kind <> 'splash' and a->>'kind' in ('question', 'write', 'multi') then a->>'kind' else kind end,
        write_max = greatest(1, least(50, coalesce((a->>'write_max')::int, write_max))), updated_at = now()
      where id = v_id;
    p := (select x from public.polls x where x.id = v_id);
  elsif p_action = 'delete' then
    delete from public.polls where id = v_id;
    return '{}'::jsonb;
  elsif p_action = 'start' then
    if exists (select 1 from public.polls q where q.id = v_id and q.kind = 'splash') then raise exception 'Užsklanda nėra balsavimas'; end if;
    update public.poll_sets set display = null where id = (select q.set_id from public.polls q where q.id = v_id);
    p := public.poll_do_start(v_id, coalesce((a->>'delay')::int, 0));
  elsif p_action = 'show' then
    -- the results screen shows this question's nominees, or its winner chosen beforehand (no voting)
    p := (select x from public.polls x where x.id = v_id);
    if p.id is null then raise exception 'Klausimas nerastas'; end if;
    if (a->>'mode' = 'splash') <> (p.kind = 'splash') then raise exception 'Netinkamas rodymas'; end if;
    if a->>'mode' = 'winner' and p.kind in ('write', 'multi') and not exists (select 1 from public.poll_votes v where v.poll_id = p.id and v.round = p.round) then
      raise exception 'Dar niekas neįrašė vardo'; end if;
    if a->>'mode' = 'winner' and p.kind not in ('write', 'multi') and not exists (select 1 from public.poll_votes v where v.poll_id = p.id and v.round = p.round) and not exists (select 1 from jsonb_array_elements(p.options) o where o->>'winner' = 'true') then
      raise exception 'Nugalėtojas nepažymėtas'; end if;
    update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
      where set_id = p.set_id and ends_at > now();
    update public.poll_sets set display = jsonb_build_object('mode', case when a->>'mode' in ('winner', 'splash', 'nomination') then a->>'mode' else 'nominees' end, 'poll', p.id, 'at', now(),
          'topic', case when p.kind = 'multi' and coalesce(a->>'topic', '') <> '' then a->>'topic' end),
        updated_at = now()
      where id = p.set_id;
    return (select to_jsonb(x) from public.poll_sets x where x.id = p.set_id);
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
