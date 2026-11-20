-- ============================================================
-- Balsavimai, 13 dalis (paleisti po polls12.sql): „Parodyti nominaciją“
-- rezultatų ekrane rodo ir balsavimo QR kodą.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

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
          'vote_token', s.vote_token);
      end if;
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
