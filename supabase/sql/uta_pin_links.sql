-- ============================================================
-- „Kuro kortelė“ renginio laiške: vairuotojas atsidaro nuorodą, nufotografuoja UTA kortelės
-- priekį ir galą – funkcija „uta-pin“ nuskaito kortelės numerį ir parodo jos PIN.
--  * uta_pin_links – nuoroda vienam renginiui: galioja renginio dienomis (diena prieš ir po),
--    tik to renginio automobilių kortelėms (card_ids; tuščia – visoms aktyvioms kortelėms)
--  * uta_pin_views – kas, kada ir kurios kortelės PIN žiūrėjo (ir nepavykę bandymai)
-- PIN pačios nuorodos niekada nerodo – tik „uta-pin“ (service role), kai nuotraukoje rasta kortelė.
-- Reikia: uta.sql, uta_pins.sql. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.uta_pin_links (
  token      text primary key,
  event_id   text not null unique,
  event_name text,
  card_ids   uuid[] not null default '{}',
  valid_from date not null,
  valid_to   date not null,
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.uta_pin_views (
  id        bigserial primary key,
  token     text,
  event_name text,
  card_id   uuid,
  card_read text,
  ok        boolean not null default false,
  reason    text,
  at        timestamptz not null default now()
);
create index if not exists uta_pin_views_token on public.uta_pin_views (token, at desc);

alter table public.uta_pin_links enable row level security;
alter table public.uta_pin_views enable row level security;
drop policy if exists "uta pin links view" on public.uta_pin_links;
create policy "uta pin links view" on public.uta_pin_links for select to authenticated using (public.can_edit('fleet') or public.can_edit('events'));
drop policy if exists "uta pin views view" on public.uta_pin_views;
create policy "uta pin views view" on public.uta_pin_views for select to authenticated using (public.can_edit('fleet'));
revoke all on public.uta_pin_links, public.uta_pin_views from anon;
grant select on public.uta_pin_links, public.uta_pin_views to authenticated;

-- the link of an event (made once, later only its days and cards change): who sends the event letter
create or replace function public.uta_pin_link_make(p_event text, p_name text, p_cards uuid[], p_from date, p_to date)
returns text language plpgsql security definer set search_path = public as $$
declare t text;
begin
  if not (public.can_edit('events') or public.can_edit('fleet')) then raise exception 'not allowed'; end if;
  if coalesce(p_event, '') = '' or p_from is null or p_to is null or p_to < p_from or p_to - p_from > 60 then raise exception 'bad dates'; end if;
  select token into t from public.uta_pin_links where event_id = p_event;
  if t is null then
    t := encode(extensions.gen_random_bytes(18), 'hex');
    insert into public.uta_pin_links (token, event_id, event_name, card_ids, valid_from, valid_to)
    values (t, p_event, left(p_name, 200), coalesce(p_cards, '{}'), p_from, p_to);
  else
    update public.uta_pin_links set event_name = left(p_name, 200), card_ids = coalesce(p_cards, '{}'), valid_from = p_from, valid_to = p_to, updated_at = now()
     where token = t;
  end if;
  return t;
end $$;
revoke all on function public.uta_pin_link_make(text, text, uuid[], date, date) from public, anon;
grant execute on function public.uta_pin_link_make(text, text, uuid[], date, date) to authenticated;

-- the page asks only whether the link works (and for which event) – nothing about cards or PINs
create or replace function public.uta_pin_link_info(p_token text)
returns jsonb language sql stable security definer set search_path = public as $$
  select case when l.token is null then jsonb_build_object('ok', false, 'why', 'none')
              when (now() at time zone 'Europe/Vilnius')::date < l.valid_from - 1 then jsonb_build_object('ok', false, 'why', 'early', 'from', l.valid_from - 1, 'event', l.event_name)
              when (now() at time zone 'Europe/Vilnius')::date > l.valid_to + 1 then jsonb_build_object('ok', false, 'why', 'late', 'event', l.event_name)
              else jsonb_build_object('ok', true, 'event', l.event_name, 'to', l.valid_to + 1) end
    from (select 1) x left join public.uta_pin_links l on l.token = p_token
$$;
revoke all on function public.uta_pin_link_info(text) from public;
grant execute on function public.uta_pin_link_info(text) to anon, authenticated;

notify pgrst, 'reload schema';
