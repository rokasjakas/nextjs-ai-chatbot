-- ============================================================
-- wishes.sql — Linkėjimai (Admin → Balsavimai → Linkėjimai, arba redaktoriaus nuoroda ?balsavimai=<raktas>)
--  * wish_boards – linkėjimų „lenta“: pavadinimas, QR nuoroda rašyti (?linketi=), ekrano nuoroda (?linkejimai=),
--    apipavidalinimas (brand), ekrano dydis, kiek sekundžių rodyti vieną linkėjimą
--  * wishes – parašyti linkėjimai: tekstas, vardas (nebūtinas), būsena new → approved (rodomas ekrane) / hidden
--  * valdo administratoriai arba turintys redaktoriaus nuorodą (tas pats poll_key_ok kaip balsavimų)
--  * rašytojai ir ekranas – be prisijungimo, tik per slaptas nuorodas; veikia tik kai balsavimai įjungti
-- Reikia: polls.sql, polls2.sql, poll_enabled.sql. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.wish_boards (
  id            uuid primary key default gen_random_uuid(),
  name          text not null default 'Linkėjimai',
  submit_token  text not null unique default replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''),
  screen_token  text not null unique default replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''),
  brand         jsonb not null default '{}'::jsonb,
  w             int not null default 1920 check (w between 100 and 8000),
  h             int not null default 1080 check (h between 100 and 8000),
  interval_sec  int not null default 10 check (interval_sec between 2 and 600),
  open          boolean not null default true,
  created_at    timestamptz not null default now()
);
create table if not exists public.wishes (
  id           uuid primary key default gen_random_uuid(),
  board_id     uuid not null references public.wish_boards(id) on delete cascade,
  text         text not null,
  name         text,
  status       text not null default 'new' check (status in ('new','approved','hidden')),
  sort         double precision,
  voter        text,
  edited       boolean not null default false,
  created_at   timestamptz not null default now(),
  approved_at  timestamptz
);
create index if not exists wishes_board_idx on public.wishes (board_id, status, created_at);
alter table public.wish_boards enable row level security;
alter table public.wishes enable row level security;
revoke all on public.wish_boards from anon, authenticated;
revoke all on public.wishes from anon, authenticated;

-- the control page: every action, for an administrator or with the editor link's key
create or replace function public.wish_admin(p_key text, p_action text, p_args jsonb default '{}'::jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare a jsonb := coalesce(p_args, '{}'::jsonb); b public.wish_boards; v_id uuid; v_new uuid; v_sort double precision;
begin
  if not public.poll_key_ok(p_key) then raise exception 'Nuoroda nebegalioja'; end if;
  if p_action = 'boards' then
    return coalesce((select jsonb_agg(to_jsonb(x) || jsonb_build_object(
        'new', (select count(*) from public.wishes w where w.board_id = x.id and w.status = 'new'),
        'shown', (select count(*) from public.wishes w where w.board_id = x.id and w.status = 'approved')) order by x.created_at desc)
      from public.wish_boards x), '[]'::jsonb);
  elsif p_action = 'board_create' then
    insert into public.wish_boards (name) values (left(coalesce(nullif(trim(a->>'name'), ''), 'Linkėjimai'), 200)) returning * into b;
    return to_jsonb(b);
  end if;
  v_id := (a->>'id')::uuid;
  if p_action = 'board_update' then
    update public.wish_boards set
      name = left(coalesce(nullif(trim(a->>'name'), ''), name), 200),
      brand = coalesce(a->'brand', brand),
      w = coalesce((a->>'w')::int, w), h = coalesce((a->>'h')::int, h),
      interval_sec = coalesce((a->>'interval_sec')::int, interval_sec),
      open = coalesce((a->>'open')::boolean, open)
    where id = v_id returning * into b;
    return to_jsonb(b);
  elsif p_action = 'board_delete' then
    delete from public.wish_boards where id = v_id; return jsonb_build_object('ok', true);
  elsif p_action = 'list' then
    return coalesce((select jsonb_agg(to_jsonb(w) - 'voter' order by coalesce(w.sort, extract(epoch from w.created_at)), w.created_at)
      from public.wishes w where w.board_id = (a->>'board')::uuid and w.status <> 'hidden'), '[]'::jsonb);
  elsif p_action = 'wish_update' then
    update public.wishes set text = left(coalesce(nullif(trim(a->>'text'), ''), text), 600),
      name = case when a ? 'name' then nullif(left(trim(a->>'name'), 80), '') else name end, edited = true
    where id = v_id; return jsonb_build_object('ok', true);
  elsif p_action = 'wish_status' then
    if coalesce(a->>'status', '') not in ('new','approved','hidden') then raise exception 'Neteisinga būsena'; end if;
    if a->>'status' = 'approved' then
      select coalesce(max(sort), 0) + 1 into v_sort from public.wishes where board_id = (select board_id from public.wishes where id = v_id) and status = 'approved';
      update public.wishes set status = 'approved', approved_at = now(), sort = v_sort where id = v_id;
    else update public.wishes set status = a->>'status' where id = v_id; end if;
    return jsonb_build_object('ok', true);
  elsif p_action = 'wish_sort' then
    update public.wishes set sort = (a->>'sort')::double precision where id = v_id; return jsonb_build_object('ok', true);
  elsif p_action = 'wish_delete' then
    delete from public.wishes where id = v_id; return jsonb_build_object('ok', true);
  elsif p_action = 'wish_add' then
    v_new := gen_random_uuid();
    select coalesce(max(sort), 0) + 1 into v_sort from public.wishes where board_id = (a->>'board')::uuid and status = 'approved';
    insert into public.wishes (id, board_id, text, name, status, sort, approved_at)
      values (v_new, (a->>'board')::uuid, left(trim(a->>'text'), 600), nullif(left(trim(coalesce(a->>'name', '')), 80), ''), 'approved', v_sort, now());
    return jsonb_build_object('id', v_new);
  end if;
  raise exception 'Nežinomas veiksmas';
end $$;
revoke all on function public.wish_admin(text, text, jsonb) from public;
grant execute on function public.wish_admin(text, text, jsonb) to anon, authenticated;

-- the QR page: the board's name and look (only while the voting module is on)
create or replace function public.wish_public(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare b public.wish_boards;
begin
  if not public.poll_enabled() then return jsonb_build_object('off', true); end if;
  select * into b from public.wish_boards where submit_token = p_token;
  if b.id is null then return null; end if;
  return jsonb_build_object('name', b.name, 'open', b.open, 'brand', b.brand);
end $$;
revoke all on function public.wish_public(text) from public;
grant execute on function public.wish_public(text) to anon, authenticated;

-- a wish written on a phone: a text (1–400 characters), a name (optional); at most 6 from one phone in 10 minutes
create or replace function public.wish_submit(p_token text, p_text text, p_name text default null, p_voter text default null) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare b public.wish_boards; t text := trim(coalesce(p_text, '')); n text := nullif(trim(coalesce(p_name, '')), '');
begin
  if not public.poll_enabled() then raise exception 'Linkėjimai išjungti'; end if;
  select * into b from public.wish_boards where submit_token = p_token;
  if b.id is null then raise exception 'Nuoroda nebegalioja'; end if;
  if not b.open then raise exception 'Linkėjimų rinkimas baigtas'; end if;
  if length(t) < 1 then raise exception 'Įrašyk linkėjimą'; end if;
  if length(t) > 400 then raise exception 'Per ilgas linkėjimas (daugiausia 400 simbolių)'; end if;
  if p_voter is not null and (select count(*) from public.wishes where board_id = b.id and voter = p_voter and created_at > now() - interval '10 minutes') >= 6 then
    raise exception 'Per daug linkėjimų iš karto – pabandyk po kelių minučių'; end if;
  if (select count(*) from public.wishes where board_id = b.id and status = 'new') >= 3000 then raise exception 'Linkėjimų per daug'; end if;
  insert into public.wishes (board_id, text, name, voter) values (b.id, t, left(n, 80), left(p_voter, 40));
  return jsonb_build_object('ok', true);
end $$;
revoke all on function public.wish_submit(text, text, text, text) from public;
grant execute on function public.wish_submit(text, text, text, text) to anon, authenticated;

-- the screen: the look, its size, how long each wish stays, and the wishes chosen to be shown (in order)
create or replace function public.wish_screen(p_token text) returns jsonb
  language plpgsql stable security definer set search_path = public as $$
declare b public.wish_boards;
begin
  if not public.poll_enabled() then return jsonb_build_object('off', true); end if;
  select * into b from public.wish_boards where screen_token = p_token;
  if b.id is null then return null; end if;
  return jsonb_build_object('name', b.name, 'brand', b.brand, 'w', b.w, 'h', b.h, 'interval_sec', b.interval_sec,
    'wishes', coalesce((select jsonb_agg(jsonb_build_object('id', w.id, 'text', w.text, 'name', w.name) order by w.sort, w.approved_at)
      from public.wishes w where w.board_id = b.id and w.status = 'approved'), '[]'::jsonb));
end $$;
revoke all on function public.wish_screen(text) from public;
grant execute on function public.wish_screen(text) to anon, authenticated;
notify pgrst, 'reload schema';
