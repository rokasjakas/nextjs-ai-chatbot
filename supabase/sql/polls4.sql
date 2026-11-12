-- ============================================================
-- Balsavimai, 4 dalis (paleisti po polls3.sql): klausimo TEMA –
-- rodoma balsavimo puslapyje ir rezultatų ekrane virš klausimo.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

alter table public.polls add column if not exists topic text not null default '';

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
    'topic', case when st in ('waiting', 'live') then nullif(p.topic, '') end,
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;

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
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'poll', p.id, 'round', p.round, 'topic', nullif(p.topic, ''), 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', coalesce(lk->'brand', p.brand),
    'w', coalesce((lk->>'w')::int, p.results_w), 'h', coalesce((lk->>'h')::int, p.results_h),
    'total', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
grant execute on function public.poll_public(text), public.poll_results(text) to anon, authenticated;

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
    insert into public.polls (topic, question, options, duration_sec, sort, created_by)
      values (left(coalesce(a->>'topic', ''), 200), left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb), coalesce((a->>'duration_sec')::int, 60),
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
        topic = left(coalesce(a->>'topic', topic), 200), question = left(coalesce(a->>'question', question), 500), options = coalesce(a->'options', options),
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
