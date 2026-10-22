-- ============================================================
-- Balsavimai, 11 dalis (paleisti po polls10.sql): ĮRAŠOMI VARDAI
--  * tas pats vardas vienam žmogui – tik kartą (ir labai panašus)
--  * labai panašus į jau įrašytą vardas priskiriamas jam, pvz.
--    „Vardas Vardeni“ → „Vardas Vardenis“. Panašu, kai: lietuviškos raidės,
--    didžiosios raidės, tarpai ir skyrybos ženklai nesvarbūs, žodžiai gali
--    būti sukeisti; kiekviename žodyje 1 klaida (ilguose, nuo 9 raidžių – 2),
--    pirmoji raidė ta pati, trumpi žodžiai (iki 4 raidžių) – tik tiksliai
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

-- letters only, without Lithuanian (and other) accents: „Vardėnis  VARDAS“ → „vardenis vardas“
create or replace function public.poll_name_norm(t text) returns text language sql immutable as $$
  select btrim(regexp_replace(regexp_replace(translate(lower(coalesce(t, '')), 'ąčęėįšųūžáàäâãåçéèêëíìîïñóòöôõúùûüýÿłńśźż', 'aceeisuuzaaaaaaceeeeiiiinooooouuuuyylnszz'), '[^a-z0-9 ]', ' ', 'g'), '\s+', ' ', 'g'))
$$;

-- edit distance: letters to add, remove or change; two neighbouring letters swapped count as one
create or replace function public.poll_lev(a text, b text) returns int language plpgsql immutable as $$
declare la int := length(a); lb int := length(b); pp int[]; prev int[]; cur int[]; i int; j int; c int; v int;
begin
  if a = b then return 0; end if;
  if la = 0 then return lb; end if;
  if lb = 0 then return la; end if;
  prev := array(select generate_series(0, lb));
  for i in 1..la loop
    cur := array[i];
    for j in 1..lb loop
      c := case when substr(a, i, 1) = substr(b, j, 1) then 0 else 1 end;
      v := least(prev[j + 1] + 1, cur[j] + 1, prev[j] + c);
      if i > 1 and j > 1 and substr(a, i, 1) = substr(b, j - 1, 1) and substr(a, i - 1, 1) = substr(b, j, 1) then v := least(v, pp[j - 1] + 1); end if;
      cur := cur || v;
    end loop;
    pp := prev; prev := cur;
  end loop;
  return prev[lb + 1];
end $$;

-- two words are the same name word: equal, or a small typo with the same first letter
create or replace function public.poll_word_near(x text, y text) returns boolean language sql immutable as $$
  select x = y or (left(x, 1) = left(y, 1) and greatest(length(x), length(y)) > 4
    and public.poll_lev(x, y) <= case when greatest(length(x), length(y)) <= 8 then 1 else 2 end)
$$;

-- two names (already normalized) are the same person: the same number of words, each near – in order or swapped
create or replace function public.poll_name_near(a text, b text) returns boolean language plpgsql immutable as $$
declare wa text[] := string_to_array(a, ' '); wb text[] := string_to_array(b, ' '); sa text[]; sb text[]; i int; ok boolean;
begin
  if a = b then return true; end if;
  if coalesce(array_length(wa, 1), 0) = 0 or coalesce(array_length(wa, 1), 0) <> coalesce(array_length(wb, 1), 0) then return false; end if;
  ok := true;
  for i in 1..array_length(wa, 1) loop
    if not public.poll_word_near(wa[i], wb[i]) then ok := false; exit; end if;
  end loop;
  if ok then return true; end if;
  sa := array(select w from unnest(wa) w order by w);
  sb := array(select w from unnest(wb) w order by w);
  for i in 1..array_length(sa, 1) loop
    if not public.poll_word_near(sa[i], sb[i]) then return false; end if;
  end loop;
  return true;
end $$;

-- typed names: one submission per phone, up to write_max different names;
-- a name near one already written counts for it; the same name twice in one submission – 'dup'
create or replace function public.poll_write(p_token text, p_names text[], p_voter text, p_poll uuid) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls; s public.poll_sets; t text; nm text; k text; ks text[] := '{}'; es text[] := '{}';
begin
  s := (select x from public.poll_sets x where x.vote_token = p_token);
  if s.id is not null then p := (select x from public.polls x where x.id = p_poll and x.set_id = s.id);
  else p := (select x from public.polls x where x.vote_token = p_token); end if;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if p.kind <> 'write' or coalesce(length(p_voter), 0) not between 8 and 100 then return 'bad'; end if;
  -- one name at a time for this nomination, so near names written at the same moment still meet
  perform pg_advisory_xact_lock(hashtext('poll_write:' || p.id::text));
  if exists (select 1 from public.poll_votes where poll_id = p.id and round = p.round and voter = p_voter) then return 'already'; end if;
  foreach t in array coalesce(p_names, '{}'::text[]) loop
    t := left(regexp_replace(btrim(coalesce(t, '')), '\s+', ' ', 'g'), 80);
    nm := public.poll_name_norm(t);
    continue when nm = '';
    -- the same person already written (the most written one if several are near)
    k := (select z.k from (select v.option_id k, count(*) n from public.poll_votes v where v.poll_id = p.id and v.round = p.round group by v.option_id) z
           where public.poll_name_near(nm, public.poll_name_norm(substr(z.k, 3))) order by z.n desc, z.k limit 1);
    k := coalesce(k, (select x from unnest(ks) x where public.poll_name_near(nm, public.poll_name_norm(substr(x, 3))) limit 1), 'w:' || nm);
    if k = any(ks) then return 'dup'; end if;
    ks := ks || k; es := es || t;
  end loop;
  if coalesce(array_length(ks, 1), 0) = 0 then return 'bad'; end if;
  if array_length(ks, 1) > p.write_max then return 'limit'; end if;
  insert into public.poll_votes (poll_id, round, option_id, voter, entry) select p.id, p.round, ks[i], p_voter, es[i] from generate_subscripts(ks, 1) i;
  return 'ok';
end $$;
revoke all on function public.poll_write(text, text[], text, uuid) from public;
grant execute on function public.poll_write(text, text[], text, uuid) to anon, authenticated;

-- the name shown for a person: the spelling written most often, on a tie the first one written
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
      if p.id is not null and s.display->>'mode' = 'splash' then
        return jsonb_build_object('state', 'splash', 'now', now(), 'poll', p.id, 'at', s.display->>'at', 'topic', nullif(p.topic, ''),
          'splash', p.brand, 'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all);
      end if;
      if p.id is not null then
        return jsonb_build_object('state', case when s.display->>'mode' = 'winner' then 'reveal' else 'nominees' end, 'now', now(),
          'poll', p.id, 'round', p.round, 'at', s.display->>'at', 'topic', nullif(p.topic, ''), 'question', p.question,
          'brand', s.brand, 'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all,
          'options', case when p.kind = 'write' then
                        -- typed names: the most written one(s) win, shown only now
                        (select coalesce(jsonb_agg(jsonb_build_object('id', z.k, 'text', z.t, 'winner', s.display->>'mode' = 'winner' and z.n = z.m) order by z.n desc, z.t), '[]'::jsonb) from (
                           select v.option_id k, count(*) n, max(count(*)) over () m,
                                  (select v2.entry from public.poll_votes v2 where v2.poll_id = p.id and v2.round = p.round and v2.option_id = v.option_id
                                     group by v2.entry order by count(*) desc, min(v2.id) limit 1) t
                             from public.poll_votes v where v.poll_id = p.id and v.round = p.round
                             group by v.option_id order by count(*) desc, v.option_id limit 15) z)
                      else (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                        'winner', s.display->>'mode' = 'winner' and coalesce(o->>'winner', '') = 'true') order by n), '[]'::jsonb)
                      from jsonb_array_elements(p.options) with ordinality as x(o, n)) end);
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
  -- typed names on the voting's screen: when the time is up only "voting ended" – the winner waits for the editor's button
  if perm and p.kind = 'write' and public.poll_state(p) = 'ended' then
    return jsonb_build_object('state', 'ended', 'hold', true, 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
      'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', s.brand, 'multi', p.multi, 'write', true,
      'w', s.results_w, 'h', s.results_h, 'show_all', s.show_all, 'vote_token', s.vote_token, 'total', 0, 'options', '[]'::jsonb);
  end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(s.brand, p.brand), 'multi', p.multi,
    'w', coalesce(s.results_w, p.results_w), 'h', coalesce(s.results_h, p.results_h), 'show_all', coalesce(s.show_all, true),
    'vote_token', case when perm then s.vote_token end,
    'write', p.kind = 'write',
    'total', (select count(distinct v.voter) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', case when p.kind = 'write' then
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

