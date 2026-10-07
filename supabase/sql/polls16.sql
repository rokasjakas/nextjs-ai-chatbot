-- ============================================================
-- Balsavimai, 16 dalis – PATAISYMAS: „Nepavyko išsiųsti“ balsuojant
-- nominacijoje su keliomis temomis (ir su įrašomais vardais).
--  * sudeda viską, ko reikia vardų įrašymui (stulpeliai, panašių vardų
--    atpažinimas iš polls11.sql, poll_mwrite) – nesvarbu, kurie ankstesni
--    failai buvo paleisti
--  * liepia Supabase iš naujo nuskaityti funkcijų sąrašą
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

alter table public.polls add column if not exists kind text not null default 'question';
alter table public.polls add column if not exists write_max int not null default 1;
alter table public.poll_votes add column if not exists entry text;

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

-- Supabase: read the list of functions again (new ones are callable at once)
notify pgrst, 'reload schema';
