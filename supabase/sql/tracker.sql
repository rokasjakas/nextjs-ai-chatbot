-- ============================================================
-- „Team Tracker“: darbo laiko apskaita (kaip Connecteam „Time Clock“)
--  * tracker_members – Team Tracker nariai: vardas ir PIN kodas (PIN saugomas tik
--                      kaip maiša). Kiekvienas narys prisijungia atskirai savo PIN,
--                      tame pačiame telefone gali dirbti keli nariai.
--  * time_shifts     – pamaina: nuo „Pradėti darbą“ iki „Baigti darbą“
--  * time_entries    – pamainos dalys: sandėlis, vairavimas, budėjimas, montažas,
--                      demontažas, operatorius, pertrauka
--  * narys susietas su programėlės paskyra: viena paskyra – vienas narys (registruojasi vieną kartą)
--  * visiems matoma tik narių sąrašas (kiek užregistruota). Nario laiką mato pats narys
--    (savo paskyra arba prisijungęs jo PIN); Admin, Office ir Projektų vadovai – visų narių
--    (be PIN); Tech, Freelance, Runner – tik savo
--  * pamiršus PIN: į paskyros el. paštą siunčiama nuoroda (galioja 1 val.) – ją siunčia
--    funkcija push-notify (RESEND_API_KEY), PIN pakeičiamas per tt_pin_reset
--  * viskas tik per funkcijas tt_* (lentelių tiesiogiai neskaito niekas);
--    5 neteisingi PIN – 5 min. palaukti
--  * kas valandą priminimą „Team Tracker aktyvus“ siunčia push-notify (jau veikiantis
--    kas 5 min. darbas) – po šio failo iš naujo įdiek funkciją push-notify
--  * pridedamas „Demo darbuotojas“ (PIN 0000) su atsitiktinėmis 2 savaičių pamainomis
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.tracker_members (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  pin_hash      text not null,
  demo          boolean not null default false,
  fails         integer not null default 0,
  locked_until  timestamptz,
  created_by    uuid default auth.uid(),
  created_at    timestamptz not null default now()
);
create unique index if not exists tracker_members_name on public.tracker_members (lower(name));
alter table public.tracker_members add column if not exists user_id uuid references auth.users(id) on delete set null;
alter table public.tracker_members add column if not exists reset_sent_at timestamptz;
create unique index if not exists tracker_members_user on public.tracker_members (user_id) where user_id is not null;

-- „Pamiršau PIN“: vienkartinės nuorodos (galioja 1 val.)
create table if not exists public.tracker_pin_resets (
  token_hash  text primary key,
  member_id   uuid not null references public.tracker_members(id) on delete cascade,
  expires_at  timestamptz not null default now() + interval '1 hour',
  used_at     timestamptz,
  created_at  timestamptz not null default now()
);
alter table public.tracker_pin_resets enable row level security;
revoke all on public.tracker_pin_resets from anon, authenticated;

create table if not exists public.tracker_tokens (
  token_hash  text primary key,
  member_id   uuid not null references public.tracker_members(id) on delete cascade,
  user_id     uuid default auth.uid(),
  created_at  timestamptz not null default now()
);

create table if not exists public.time_shifts (
  id           uuid primary key default gen_random_uuid(),
  member_id    uuid not null references public.tracker_members(id) on delete cascade,
  started_by   uuid,                       -- the app account that pressed „Pradėti“ (gets the reminders)
  started_at   timestamptz not null default now(),
  ended_at     timestamptz,
  reminded_at  timestamptz,
  created_at   timestamptz not null default now()
);
create index if not exists time_shifts_member_time on public.time_shifts (member_id, started_at desc);
create unique index if not exists time_shifts_one_open on public.time_shifts (member_id) where ended_at is null;

create table if not exists public.time_entries (
  id          uuid primary key default gen_random_uuid(),
  shift_id    uuid not null references public.time_shifts(id) on delete cascade,
  kind        text not null check (kind in ('warehouse','driving','standby','setup','teardown','operator','break')),
  started_at  timestamptz not null default now(),
  ended_at    timestamptz
);
create index if not exists time_entries_shift on public.time_entries (shift_id, started_at);
create unique index if not exists time_entries_one_open on public.time_entries (shift_id) where ended_at is null;

alter table public.tracker_members enable row level security;
alter table public.tracker_tokens enable row level security;
alter table public.time_shifts enable row level security;
alter table public.time_entries enable row level security;
revoke all on public.tracker_members, public.tracker_tokens, public.time_shifts, public.time_entries from anon, authenticated;

-- ---------- pagalbinės ----------
-- who may see every member's time: Admin, Office, Projektų vadovas (Tech, Freelance, Runner – only their own)
create or replace function public.tt_manager() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','office','pm'), false)
$$;
-- PIN or the device's sign-in key (token); null = allowed. A manager / the member's own account may pass nothing (to look).
create or replace function public.tt_auth(m uuid, p_pin text, p_token text, admin_ok boolean) returns text
  language plpgsql security definer set search_path = public, extensions as $$
declare r public.tracker_members;
begin
  if auth.uid() is null or not public.is_approved() then return 'Reikia prisijungti prie programėlės.'; end if;
  select * into r from public.tracker_members where id = m;
  if r.id is null then return 'Tokio nario nėra.'; end if;
  if p_token is not null and exists (select 1 from public.tracker_tokens where member_id = m and token_hash = encode(digest(p_token, 'sha256'), 'hex')) then return null; end if;
  if p_pin is null then
    -- looking at the time (admin_ok): the member's own account, or Admin / Office / Projektų vadovas
    if admin_ok and (r.user_id = auth.uid() or public.tt_manager()) then return null; end if;
    return 'Prisijunk savo PIN kodu.';
  end if;
  if r.locked_until is not null and r.locked_until > now() then return 'Per daug neteisingų bandymų – palauk kelias minutes.'; end if;
  if r.pin_hash = crypt(p_pin, r.pin_hash) then
    update public.tracker_members set fails = 0, locked_until = null where id = m;
    return null;
  end if;
  update public.tracker_members set fails = case when fails >= 4 then 0 else fails + 1 end,
    locked_until = case when fails >= 4 then now() + interval '5 minutes' else locked_until end where id = m;
  return 'Neteisingas PIN kodas.';
end $$;

create or replace function public.tt_shift_json(sid uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', s.id, 'started_at', s.started_at, 'ended_at', s.ended_at,
    'entries', coalesce((select jsonb_agg(jsonb_build_object('kind', e.kind, 'started_at', e.started_at, 'ended_at', e.ended_at) order by e.started_at)
                         from public.time_entries e where e.shift_id = s.id), '[]'::jsonb))
  from public.time_shifts s where s.id = sid
$$;

create or replace function public.tt_state_of(m uuid) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shift', (select public.tt_shift_json(id) from public.time_shifts where member_id = m and ended_at is null),
    'last', (select public.tt_shift_json(id) from public.time_shifts where member_id = m and ended_at is not null order by ended_at desc limit 1))
$$;

-- ---------- visiems: narių sąrašas (kiek užregistruota) ----------
create or replace function public.tt_members() returns jsonb
  language sql stable security definer set search_path = public as $$
  select case when public.is_approved() then coalesce((select jsonb_agg(jsonb_build_object('id', id, 'name', name, 'demo', demo, 'created_at', created_at, 'mine', user_id = auth.uid(), 'mail', user_id is not null) order by demo, lower(name)) from public.tracker_members), '[]'::jsonb) else '[]'::jsonb end
$$;

create or replace function public.tt_register(p_name text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare nm text := btrim(coalesce(p_name, '')); mid uuid; tok text;
begin
  if auth.uid() is null or not public.is_approved() then return jsonb_build_object('error', 'Reikia prisijungti prie programėlės.'); end if;
  if length(nm) < 2 or length(nm) > 60 then return jsonb_build_object('error', 'Įrašyk vardą ir pavardę.'); end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4,8}$' then return jsonb_build_object('error', 'PIN – 4–8 skaitmenys.'); end if;
  if exists (select 1 from public.tracker_members where user_id = auth.uid()) then return jsonb_build_object('error', 'Tu jau užregistruotas Team Tracker – prisijunk savo PIN (pamiršus – „Pamiršau PIN“).'); end if;
  if exists (select 1 from public.tracker_members where lower(name) = lower(nm)) then return jsonb_build_object('error', 'Toks narys jau užregistruotas.'); end if;
  insert into public.tracker_members (name, pin_hash, user_id) values (nm, crypt(p_pin, gen_salt('bf')), auth.uid()) returning id into mid;
  tok := encode(gen_random_bytes(24), 'hex');
  insert into public.tracker_tokens (token_hash, member_id) values (encode(digest(tok, 'sha256'), 'hex'), mid);
  return jsonb_build_object('token', tok, 'state', public.tt_state_of(mid));
end $$;

-- prisijungimas PIN kodu: šiam įrenginiui grąžinamas raktas (PIN neįsimenamas)
create or replace function public.tt_login(m uuid, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; tok text;
begin
  err := public.tt_auth(m, coalesce(p_pin, ''), null, false);
  if err is not null then return jsonb_build_object('error', err); end if;
  -- a member registered before accounts were linked: tied to the first account that signs in with the PIN
  update public.tracker_members set user_id = auth.uid()
   where id = m and user_id is null and not demo and not exists (select 1 from public.tracker_members where user_id = auth.uid());
  tok := encode(gen_random_bytes(24), 'hex');
  insert into public.tracker_tokens (token_hash, member_id) values (encode(digest(tok, 'sha256'), 'hex'), m);
  return jsonb_build_object('token', tok, 'state', public.tt_state_of(m));
end $$;

create or replace function public.tt_logout(m uuid, p_token text) returns void
  language sql security definer set search_path = public, extensions as $$
  delete from public.tracker_tokens where member_id = m and token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
$$;

create or replace function public.tt_state(m uuid, p_token text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return public.tt_state_of(m);
end $$;

-- „Pradėti darbą“
create or replace function public.tt_start(m uuid, p_token text, p_kind text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  if exists (select 1 from public.time_shifts where member_id = m and ended_at is null) then return public.tt_state_of(m); end if;
  insert into public.time_shifts (member_id, started_by) values (m, auth.uid()) returning id into sid;
  insert into public.time_entries (shift_id, kind) values (sid, p_kind);
  return public.tt_state_of(m);
end $$;

-- veiklos pakeitimas: ankstesnė užbaigiama ir išsaugoma, nauja pradedama dabar
create or replace function public.tt_switch(m uuid, p_token text, p_kind text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid; cur text;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select id into sid from public.time_shifts where member_id = m and ended_at is null;
  if sid is null then return jsonb_build_object('error', 'Darbas nepradėtas.'); end if;
  select kind into cur from public.time_entries where shift_id = sid and ended_at is null;
  if cur is distinct from p_kind then
    update public.time_entries set ended_at = now() where shift_id = sid and ended_at is null;
    insert into public.time_entries (shift_id, kind) values (sid, p_kind);
  end if;
  return public.tt_state_of(m);
end $$;

-- „Baigti darbą“ (p_at – jei pamiršai baigti: ankstesnis laikas, bet ne ankstesnis už paskutinės veiklos pradžią)
create or replace function public.tt_stop(m uuid, p_token text, p_at timestamptz default null) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text; sid uuid; last_start timestamptz; t timestamptz;
begin
  err := public.tt_auth(m, null, p_token, false);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  select id into sid from public.time_shifts where member_id = m and ended_at is null;
  if sid is null then return public.tt_state_of(m); end if;
  select max(started_at) into last_start from public.time_entries where shift_id = sid;
  t := least(now(), greatest(coalesce(p_at, now()), coalesce(last_start, now())));
  update public.time_entries set ended_at = t where shift_id = sid and ended_at is null;
  update public.time_shifts set ended_at = t where id = sid;
  return public.tt_state_of(m);
end $$;

-- nario pamainos per laikotarpį (prisijungus; administratoriui – be PIN)
create or replace function public.tt_report(m uuid, p_token text, p_from timestamptz, p_to timestamptz) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  err := public.tt_auth(m, null, p_token, true);
  if err is not null then return jsonb_build_object('error', err, 'auth', true); end if;
  return jsonb_build_object('member', (select jsonb_build_object('id', id, 'name', name, 'demo', demo) from public.tracker_members where id = m),
    'shifts', coalesce((select jsonb_agg(public.tt_shift_json(s.id) order by s.started_at desc) from public.time_shifts s
       where s.member_id = m and s.started_at < p_to and coalesce(s.ended_at, now()) > p_from), '[]'::jsonb));
end $$;

-- nario ištrynimas su visu jo laiku: pats narys (savo paskyra / PIN / raktu) arba administratorius
create or replace function public.tt_delete(m uuid, p_token text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare err text;
begin
  if public.is_admin() or exists (select 1 from public.tracker_members where id = m and user_id = auth.uid()) then err := null;
  else err := public.tt_auth(m, p_pin, p_token, false); end if;
  if err is not null then return jsonb_build_object('error', err); end if;
  delete from public.tracker_members where id = m;
  return jsonb_build_object('ok', true);
end $$;

-- naujas PIN pagal nuorodą iš laiško (veikia ir neprisijungus prie programėlės; nuoroda vienkartinė, 1 val.)
create or replace function public.tt_pin_reset(p_token text, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare r public.tracker_pin_resets; nm text;
begin
  select * into r from public.tracker_pin_resets where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  if r.token_hash is null or r.used_at is not null then return jsonb_build_object('error', 'Nuoroda neteisinga arba jau panaudota.'); end if;
  if r.expires_at < now() then return jsonb_build_object('error', 'Nuoroda nebegalioja (galiojo 1 val.) – paprašyk naujos.'); end if;
  if p_pin is null then select name into nm from public.tracker_members where id = r.member_id; return jsonb_build_object('name', nm); end if;
  if p_pin !~ '^[0-9]{4,8}$' then return jsonb_build_object('error', 'PIN – 4–8 skaitmenys.'); end if;
  update public.tracker_members set pin_hash = crypt(p_pin, gen_salt('bf')), fails = 0, locked_until = null where id = r.member_id returning name into nm;
  update public.tracker_pin_resets set used_at = now() where member_id = r.member_id and used_at is null;
  delete from public.tracker_tokens where member_id = r.member_id;   -- every device signs in again with the new PIN
  return jsonb_build_object('ok', true, 'name', nm);
end $$;
-- administratorius nustato nariui naują PIN (kai laiškas neateina ar narys be paskyros)
create or replace function public.tt_set_pin(m uuid, p_pin text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.is_admin() then return jsonb_build_object('error', 'PIN keisti gali tik administratorius.'); end if;
  if coalesce(p_pin, '') !~ '^[0-9]{4,8}$' then return jsonb_build_object('error', 'PIN – 4–8 skaitmenys.'); end if;
  update public.tracker_members set pin_hash = crypt(p_pin, gen_salt('bf')), fails = 0, locked_until = null where id = m and not demo;
  if not found then return jsonb_build_object('error', 'Tokio nario nėra.'); end if;
  delete from public.tracker_tokens where member_id = m;
  return jsonb_build_object('ok', true);
end $$;
revoke all on function public.tt_set_pin(uuid, text) from public, anon;
grant execute on function public.tt_set_pin(uuid, text) to authenticated;
revoke all on function public.tt_pin_reset(text, text) from public;
grant execute on function public.tt_pin_reset(text, text) to anon, authenticated;

revoke all on function public.tt_auth(uuid, text, text, boolean), public.tt_shift_json(uuid), public.tt_state_of(uuid), public.tt_manager() from public, anon, authenticated;
revoke all on function public.tt_members(), public.tt_register(text, text), public.tt_login(uuid, text), public.tt_logout(uuid, text),
  public.tt_state(uuid, text), public.tt_start(uuid, text, text), public.tt_switch(uuid, text, text), public.tt_stop(uuid, text, timestamptz),
  public.tt_report(uuid, text, timestamptz, timestamptz), public.tt_delete(uuid, text, text) from public, anon;
grant execute on function public.tt_members(), public.tt_register(text, text), public.tt_login(uuid, text), public.tt_logout(uuid, text),
  public.tt_state(uuid, text), public.tt_start(uuid, text, text), public.tt_switch(uuid, text, text), public.tt_stop(uuid, text, timestamptz),
  public.tt_report(uuid, text, timestamptz, timestamptz), public.tt_delete(uuid, text, text) to authenticated;

-- ---------- demo darbuotojas: 2 savaičių darbo dienos su atsitiktinėmis veiklomis ----------
do $$
declare mid uuid; d date; t timestamptz; sid uuid; k text; n int; i int; dur int; br boolean;
  kinds text[] := array['warehouse','driving','standby','setup','teardown','operator'];
begin
  if exists (select 1 from public.tracker_members where demo) then return; end if;
  insert into public.tracker_members (name, pin_hash, demo, created_by)
    values ('Demo darbuotojas', extensions.crypt('0000', extensions.gen_salt('bf')), true, null) returning id into mid;
  for d in select generate_series(current_date - 14, current_date - 1, interval '1 day')::date loop
    continue when extract(isodow from d) in (6, 7);
    t := (d + time '07:30' + make_interval(mins => (random() * 90)::int)) at time zone 'Europe/Vilnius';
    insert into public.time_shifts (member_id, started_at) values (mid, t) returning id into sid;
    n := 3 + (random() * 3)::int; br := false;
    for i in 1..n loop
      if not br and i > 1 and random() < 0.6 then
        k := 'break'; dur := 20 + (random() * 25)::int; br := true;
      else
        k := kinds[1 + (random() * 5)::int]; dur := 45 + (random() * 150)::int;
      end if;
      insert into public.time_entries (shift_id, kind, started_at, ended_at) values (sid, k, t, t + make_interval(mins => dur));
      t := t + make_interval(mins => dur);
    end loop;
    update public.time_shifts set ended_at = t where id = sid;
  end loop;
end $$;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';
