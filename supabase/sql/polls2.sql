-- ============================================================
-- Balsavimai, 2 dalis (paleisti po polls.sql):
--  * redaktoriaus nuoroda (?balsavimai=<raktas>): kas ją turi, tas be
--    prisijungimo kuria, redaguoja, paleidžia ir stabdo balsavimus.
--    Nuorodą sukuria / pakeičia / išjungia administratorius.
--  * visi redaktoriaus veiksmai – per vieną funkciją poll_admin
--    (administratoriui arba su galiojančiu raktu)
--  * fonas, logotipas ir šriftas saugomi duomenų bazėje (poll_assets),
--    todėl įkelti gali ir redaktorius be prisijungimo
--  * klausimų eiliškumas (sort)
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.polls add column if not exists sort int not null default 0;

create table if not exists public.poll_settings (
  id           int primary key default 1 check (id = 1),
  editor_token text,
  editor_on    boolean not null default false,
  updated_at   timestamptz not null default now()
);
alter table public.poll_settings enable row level security;
revoke all on public.poll_settings from anon, authenticated;

create table if not exists public.poll_assets (
  id         uuid primary key default gen_random_uuid(),
  mime       text not null,
  data       text not null,                    -- base64
  bytes      int not null,
  created_at timestamptz not null default now()
);
alter table public.poll_assets enable row level security;
revoke all on public.poll_assets from anon, authenticated;

-- administratorius arba galiojantis redaktoriaus raktas
create or replace function public.poll_key_ok(p_key text) returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.is_admin(), false)
      or (coalesce(length(p_key), 0) = 64
          and exists (select 1 from public.poll_settings s where s.id = 1 and s.editor_on and s.editor_token = p_key))
$$;
revoke all on function public.poll_key_ok(text) from public;

-- administratoriui: redaktoriaus nuoroda ('get' | 'new' | 'on' | 'off')
create or replace function public.poll_editor_link(p_action text) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare s public.poll_settings; t text := replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');
begin
  if not coalesce(public.is_admin(), false) then raise exception 'Tik administratoriui'; end if;
  if p_action = 'new' then
    insert into public.poll_settings (id, editor_token, editor_on) values (1, t, true)
      on conflict (id) do update set editor_token = t, editor_on = true, updated_at = now();
  elsif p_action = 'on' then
    insert into public.poll_settings (id, editor_token, editor_on) values (1, t, true)
      on conflict (id) do update set editor_on = true, editor_token = coalesce(poll_settings.editor_token, t), updated_at = now();
  elsif p_action = 'off' then
    update public.poll_settings set editor_on = false, updated_at = now() where id = 1;
  end if;
  select * into s from public.poll_settings where id = 1;
  return jsonb_build_object('token', case when s.editor_on then s.editor_token end, 'on', coalesce(s.editor_on, false));
end $$;
revoke all on function public.poll_editor_link(text) from public, anon;
grant execute on function public.poll_editor_link(text) to authenticated;

-- paleisti / sustabdyti (bendra administratoriui ir redaktoriui)
create or replace function public.poll_do_start(p_id uuid, p_delay int) returns public.polls
  language plpgsql security definer set search_path = public as $$
declare p public.polls; t timestamptz := now() + make_interval(secs => greatest(0, least(coalesce(p_delay, 0), 86400)));
begin
  update public.polls set
      vote_token = case when round = 0 and starts_at is null then vote_token
                        else replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '') end,
      round = round + 1, starts_at = t, ends_at = t + make_interval(secs => duration_sec), updated_at = now()
    where id = p_id returning * into p;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return p;
end $$;
create or replace function public.poll_do_stop(p_id uuid) returns public.polls
  language plpgsql security definer set search_path = public as $$
declare p public.polls;
begin
  update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
    where id = p_id and ends_at > now() returning * into p;
  if p.id is null then select * into p from public.polls where id = p_id; end if;
  return p;
end $$;
revoke all on function public.poll_do_start(uuid, int), public.poll_do_stop(uuid) from public, anon, authenticated;

create or replace function public.poll_start(p_id uuid, p_delay int default 0) returns public.polls
  language plpgsql security definer set search_path = public as $$
begin
  if not coalesce(public.is_admin(), false) then raise exception 'Tik administratoriui'; end if;
  return public.poll_do_start(p_id, p_delay);
end $$;
create or replace function public.poll_stop(p_id uuid) returns public.polls
  language plpgsql security definer set search_path = public as $$
begin
  if not coalesce(public.is_admin(), false) then raise exception 'Tik administratoriui'; end if;
  return public.poll_do_stop(p_id);
end $$;

-- visi redaktoriaus veiksmai
create or replace function public.poll_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); p public.polls; v_id uuid; v_new uuid;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  if p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.sort, x.created_at) from public.polls x), '[]'::jsonb);
  elsif p_action = 'create' then
    insert into public.polls (question, options, duration_sec, brand, results_w, results_h, sort, created_by)
      values (left(coalesce(a->>'question', ''), 500), coalesce(a->'options', '[]'::jsonb), coalesce((a->>'duration_sec')::int, 60),
              coalesce(a->'brand', '{}'::jsonb), coalesce((a->>'results_w')::int, 1920), coalesce((a->>'results_h')::int, 1080),
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
        duration_sec = coalesce((a->>'duration_sec')::int, duration_sec), brand = coalesce(a->'brand', brand),
        results_w = coalesce((a->>'results_w')::int, results_w), results_h = coalesce((a->>'results_h')::int, results_h),
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

-- fonas / logotipas / šriftas balsavimo ir rezultatų puslapiams (viešai)
create or replace function public.poll_asset(p_id uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('mime', mime, 'data', data) from public.poll_assets where id = p_id
$$;
revoke all on function public.poll_asset(uuid) from public;
grant execute on function public.poll_asset(uuid) to anon, authenticated;
