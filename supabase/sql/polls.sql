-- ============================================================
-- Balsavimai (Admin → Balsavimai): klausimas su atsakymų variantais,
-- balsuojama telefonu per QR nuorodą, rezultatai – atskira nuoroda
-- (pvz. LED ekranui / OBS, nustatyto dydžio pikseliais).
--  * tvarko tik administratoriai (lentelės matomos tik jiems)
--  * balsuotojai ir rezultatų ekranas – be prisijungimo, tik per slaptą
--    nuorodą (funkcijos poll_public / poll_vote / poll_results)
--  * pasibaigus balsavimui klausimas paslepiamas; paleidus iš naujo –
--    naujas QR kodas (senasis nebegalioja), skaičiuojama nuo nulio
--  * fonas ir šriftas – vieša saugykla „poll-assets“
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.polls (
  id            uuid primary key default gen_random_uuid(),
  question      text not null default '' check (char_length(question) <= 500),
  options       jsonb not null default '[]'::jsonb,          -- [{ id, text }]
  duration_sec  int not null default 60 check (duration_sec between 5 and 86400),
  starts_at     timestamptz,                                 -- balsavimo pradžia (gali būti ateityje)
  ends_at       timestamptz,                                 -- pabaiga
  round         int not null default 0,                      -- kelintas paleidimas (balsai skaičiuojami tik šio)
  vote_token    text not null unique default (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  results_token text not null unique default (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  brand         jsonb not null default '{}'::jsonb,          -- { bg, font, fontName, color, accent }
  results_w     int not null default 1920 check (results_w between 100 and 8000),
  results_h     int not null default 1080 check (results_h between 100 and 8000),
  created_by    uuid default auth.uid() references auth.users(id) on delete set null,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create table if not exists public.poll_votes (
  id         bigint generated always as identity primary key,
  poll_id    uuid not null references public.polls(id) on delete cascade,
  round      int not null,
  option_id  text not null,
  voter      text not null,                                  -- atsitiktinis telefono raktas
  created_at timestamptz not null default now(),
  unique (poll_id, round, voter)
);
create index if not exists poll_votes_poll on public.poll_votes (poll_id, round);

alter table public.polls enable row level security;
alter table public.poll_votes enable row level security;
revoke all on public.polls, public.poll_votes from anon, authenticated;
grant select, insert, update, delete on public.polls to authenticated;
grant select, delete on public.poll_votes to authenticated;
drop policy if exists "polls admin" on public.polls;
create policy "polls admin" on public.polls for all to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "poll votes admin" on public.poll_votes;
create policy "poll votes admin" on public.poll_votes for select to authenticated using (public.is_admin());
drop policy if exists "poll votes admin delete" on public.poll_votes;
create policy "poll votes admin delete" on public.poll_votes for delete to authenticated using (public.is_admin());

-- ---------- administratoriui: pradėti (po p_delay sekundžių) ir sustabdyti ----------
-- pirmą kartą paleidžiant QR kodas lieka tas pats (jį galima parodyti iš anksto);
-- kiekvieną kitą kartą – naujas, o balsai skaičiuojami nuo nulio
create or replace function public.poll_start(p_id uuid, p_delay int default 0) returns public.polls
  language plpgsql security definer set search_path = public as $$
declare p public.polls; t timestamptz := now() + make_interval(secs => greatest(0, least(coalesce(p_delay, 0), 86400)));
begin
  if not public.is_admin() then raise exception 'Tik administratoriui'; end if;
  update public.polls set
      vote_token = case when round = 0 and starts_at is null then vote_token
                        else replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '') end,
      round = round + 1, starts_at = t, ends_at = t + make_interval(secs => duration_sec), updated_at = now()
    where id = p_id returning * into p;
  if p.id is null then raise exception 'Balsavimas nerastas'; end if;
  return p;
end $$;

create or replace function public.poll_stop(p_id uuid) returns public.polls
  language plpgsql security definer set search_path = public as $$
declare p public.polls;
begin
  if not public.is_admin() then raise exception 'Tik administratoriui'; end if;
  update public.polls set ends_at = now(), starts_at = least(starts_at, now()), updated_at = now()
    where id = p_id and ends_at > now() returning * into p;
  if p.id is null then select * into p from public.polls where id = p_id; end if;
  return p;
end $$;
revoke all on function public.poll_start(uuid, int), public.poll_stop(uuid) from public, anon;
grant execute on function public.poll_start(uuid, int), public.poll_stop(uuid) to authenticated;

-- ---------- viešai (be prisijungimo) ----------
create or replace function public.poll_state(p public.polls) returns text language sql stable as $$
  select case when p.starts_at is null then 'draft'
              when now() < p.starts_at then 'waiting'
              when now() < p.ends_at then 'live'
              else 'ended' end
$$;

-- balsuotojo puslapis (QR): pasibaigus – klausimas nerodomas
create or replace function public.poll_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls; st text;
begin
  select * into p from public.polls where vote_token = p_token;
  if p.id is null then return jsonb_build_object('state', 'invalid', 'now', now()); end if;
  st := public.poll_state(p);
  return jsonb_build_object('state', st, 'now', now(), 'round', p.round, 'starts_at', p.starts_at, 'ends_at', p.ends_at,
    'brand', p.brand,
    'question', case when st in ('waiting', 'live') then p.question end,
    'options', case when st = 'live' then (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text')), '[]'::jsonb) from jsonb_array_elements(p.options) o) end);
end $$;

create or replace function public.poll_vote(p_token text, p_option text, p_voter text) returns text
  language plpgsql security definer set search_path = public as $$
declare p public.polls;
begin
  select * into p from public.polls where vote_token = p_token;
  if p.id is null or public.poll_state(p) <> 'live' then return 'ended'; end if;
  if coalesce(length(p_voter), 0) not between 8 and 100 then return 'bad'; end if;
  if not exists (select 1 from jsonb_array_elements(p.options) o where o->>'id' = p_option) then return 'bad'; end if;
  insert into public.poll_votes (poll_id, round, option_id, voter) values (p.id, p.round, p_option, p_voter)
    on conflict (poll_id, round, voter) do nothing;
  if not found then return 'already'; end if;
  return 'ok';
end $$;

-- rezultatų ekranas (ir redaktoriaus peržiūra): šio paleidimo balsai
create or replace function public.poll_results(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare p public.polls;
begin
  select * into p from public.polls where results_token = p_token;
  if p.id is null then return jsonb_build_object('state', 'invalid'); end if;
  return jsonb_build_object('state', public.poll_state(p), 'now', now(), 'round', p.round, 'question', p.question,
    'starts_at', p.starts_at, 'ends_at', p.ends_at, 'brand', p.brand, 'w', p.results_w, 'h', p.results_h,
    'total', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round),
    'options', (select coalesce(jsonb_agg(jsonb_build_object('id', o->>'id', 'text', o->>'text',
                  'votes', (select count(*) from public.poll_votes v where v.poll_id = p.id and v.round = p.round and v.option_id = o->>'id')) order by n), '[]'::jsonb)
                from jsonb_array_elements(p.options) with ordinality as x(o, n)));
end $$;
revoke all on function public.poll_state(public.polls), public.poll_public(text), public.poll_vote(text, text, text), public.poll_results(text) from public;
grant execute on function public.poll_public(text), public.poll_vote(text, text, text), public.poll_results(text) to anon, authenticated;
grant execute on function public.poll_state(public.polls) to authenticated;

-- ---------- fonas ir šriftas: vieša saugykla, įkelti gali tik administratoriai ----------
insert into storage.buckets (id, name, public) values ('poll-assets', 'poll-assets', true)
  on conflict (id) do update set public = true;
drop policy if exists "poll assets admin insert" on storage.objects;
create policy "poll assets admin insert" on storage.objects for insert to authenticated with check (bucket_id = 'poll-assets' and public.is_admin());
drop policy if exists "poll assets admin update" on storage.objects;
create policy "poll assets admin update" on storage.objects for update to authenticated using (bucket_id = 'poll-assets' and public.is_admin());
drop policy if exists "poll assets admin delete" on storage.objects;
create policy "poll assets admin delete" on storage.objects for delete to authenticated using (bucket_id = 'poll-assets' and public.is_admin());
