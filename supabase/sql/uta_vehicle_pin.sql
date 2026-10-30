-- ============================================================
-- QR kodas ant automobilio → „Kuro pylimas“ → tam automobiliui priskirtos UTA kortelės PIN
--  * įmonės narys, prisijungęs programėlėje ar telefono naršyklėje – PIN rodomas iš karto, kodo nereikia;
--  * ne narys – įrašo savo vairuotojo kodą (4 skaitmenys) iš renginio laiško; kodas turi būti
--    priskirtas šiam automobiliui renginyje tą dieną (diena prieš ar po – irgi tinka). Jei automobilis
--    tomis dienomis jokiame renginyje nepriskirtas – tinka bet kuris galiojantis vairuotojo kodas.
--  * į UTA ataskaitą (uta_pin_views: kas, kada, kur, kuri kortelė, renginys) nariui įrašoma tik paspaudus
--    „Registruoti kuro pylimą“ – kartu su to pylimo komentaru ir kvito nuotraukomis (log_id → vehicle_logs);
--    ne nariui – jau parodžius PIN, o užregistravus pylimą prijungiamas ir jis. Įkėlus UTA ataskaitą
--    susiejama su pylimu (uta_pin_fills.sql).
--  * vehicle_drivers – kas kurią dieną kuriuo įmonės automobiliu važiuoja (pildo programa iš renginių
--    skilties „Transportas“; FURA ir nuomoto transporto vairuotojų čia nėra – jiems kodo nereikia).
-- Super Admin gali ištrinti įrašus iš UTA ataskaitos (pvz. bandymus) – uta_pin_views_delete.
-- 5 neteisingi kodai per parą – kuro PIN šiam automobiliui užrakinamas parai (nariams – ne).
-- Reikia: invoices.sql (is_super), vehicle_qr.sql, vehicle_names.sql, driver_codes.sql, uta.sql, uta_pins.sql, uta_pin_links.sql. Saugu paleisti pakartotinai.
-- ============================================================

-- the fill registered on the QR page (its comment and receipt photos)
alter table public.uta_pin_views add column if not exists log_id uuid;

create table if not exists public.vehicle_drivers (
  event_id    text not null,
  day         date not null,
  vehicle_id  text not null,
  driver_key  text not null,
  driver_name text,
  event_name  text,
  updated_at  timestamptz not null default now(),
  primary key (event_id, day, vehicle_id, driver_key)
);
create index if not exists vehicle_drivers_veh on public.vehicle_drivers (vehicle_id, day);
alter table public.vehicle_drivers enable row level security;
drop policy if exists "vehicle drivers view" on public.vehicle_drivers;
create policy "vehicle drivers view" on public.vehicle_drivers for select to authenticated using (public.can_view('fleet') or public.can_view('events'));
revoke all on public.vehicle_drivers from anon;
grant select on public.vehicle_drivers to authenticated;

-- an event's drivers of company vehicles: p_rows [{ "d":"2026-10-14", "v":"veh_…", "k":"jonas jonaitis", "n":"Jonas Jonaitis" }]
create or replace function public.vehicle_drivers_set(p_event text, p_name text, p_rows jsonb)
returns integer language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if not public.can_edit('events') then raise exception 'not allowed'; end if;
  if coalesce(p_event, '') = '' then raise exception 'no event'; end if;
  delete from public.vehicle_drivers where event_id = p_event;
  insert into public.vehicle_drivers (event_id, day, vehicle_id, driver_key, driver_name, event_name)
  select distinct on (x->>'d', x->>'v', lower(trim(x->>'k'))) p_event, (x->>'d')::date, x->>'v', lower(trim(x->>'k')), left(trim(x->>'n'), 120), left(p_name, 200)
    from jsonb_array_elements(case when jsonb_typeof(p_rows) = 'array' then p_rows else '[]'::jsonb end) x
   where coalesce(x->>'d', '') ~ '^\d{4}-\d{2}-\d{2}$' and coalesce(x->>'v', '') <> '' and coalesce(trim(x->>'k'), '') <> ''
   limit 500;
  get diagnostics n = row_count;
  return n;
end $$;
revoke all on function public.vehicle_drivers_set(text, text, jsonb) from public, anon;
grant execute on function public.vehicle_drivers_set(text, text, jsonb) to authenticated;

create or replace function public.uta_card_mask(no text) returns text language sql immutable as $$
  select case when array_length(g, 1) >= 3 then '•••• ' || g[array_length(g, 1) - 1] || ' ' || g[array_length(g, 1)]
              else '•••• ' || right(regexp_replace(no, '[^0-9]', '', 'g'), 6) end
    from (select regexp_split_to_array(trim(coalesce(no, '')), '\s+') g) s
$$;

-- the QR page: the PIN of the vehicle's card(s)
create or replace function public.uta_vehicle_pin(p_token text, p_code text default null, p_loc jsonb default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v jsonb; vid text; vname text; tok text; who text; ev text; member boolean := false;
        d date := (now() at time zone 'Europe/Vilnius')::date; lat double precision; lng double precision; acc int;
        out jsonb := '[]'::jsonb; c record; cd text := nullif(regexp_replace(coalesce(p_code, ''), '\D', '', 'g'), ''); dkey text; dname text;
begin
  v := public.vehicle_by_token(p_token);
  if v is null then raise exception 'QR kodas nebegalioja.'; end if;
  vid := v ->> 'id'; tok := 'qr:' || vid;
  vname := concat_ws(' · ', nullif(v ->> 'name', ''), case when nullif(v ->> 'plate', '') is not null
             and position(upper(regexp_replace(v ->> 'plate', '[^0-9A-Za-z]', '', 'g')) in upper(regexp_replace(coalesce(v ->> 'name', ''), '[^0-9A-Za-z]', '', 'g'))) = 0
             then v ->> 'plate' end);
  begin
    lat := (p_loc ->> 'lat')::double precision; lng := (p_loc ->> 'lng')::double precision; acc := round((p_loc ->> 'acc')::numeric)::int;
    if lat not between -90 and 90 or lng not between -180 and 180 then lat := null; lng := null; acc := null; end if;
  exception when others then lat := null; lng := null; acc := null; end;

  if auth.uid() is not null and public.is_approved() then
    member := true; who := public.my_name();
    select event_name into ev from public.vehicle_drivers where vehicle_id = vid and day between d - 1 and d + 1 order by abs(day - d) limit 1;
  else
    if (select count(*) from public.uta_pin_views where token = tok and at > now() - interval '1 hour') >= 20 then
      raise exception 'Per daug bandymų – pabandyk po valandos.'; end if;
    if (select count(*) from public.uta_pin_views where token = tok and reason = 'neteisingas kodas' and at > now() - interval '24 hours') >= 5 then
      raise exception 'Per daug neteisingų kodų – kuro PIN šiam automobiliui užrakintas parai. Kreipkis į ofisą.'; end if;
    if cd is null or cd !~ '^[0-9]{4}$' then raise exception 'Įrašyk savo vairuotojo kodą (4 skaitmenys) iš renginio laiško.'; end if;
    select x.key, x.name into dkey, dname from public.driver_codes x where x.code = cd;
    if dkey is not null then
      select x.event_name into ev from public.vehicle_drivers x
       where x.vehicle_id = vid and x.driver_key = dkey and x.day between d - 1 and d + 1 order by abs(x.day - d) limit 1;
      -- the vehicle is someone else's in an event these days: not this code
      if not found and exists (select 1 from public.vehicle_drivers x where x.vehicle_id = vid and x.day between d - 1 and d + 1) then dkey := null; end if;
    end if;
    if dkey is null then
      insert into public.uta_pin_views (token, ok, reason, card_read, driver_name, lat, lng, acc, vehicle)
      values (tok, false, 'neteisingas kodas', left(cd, 2) || '••', null, lat, lng, acc, vname);
      return jsonb_build_object('error', 'Šis kodas šiam automobiliui šiandien nepriskirtas – patikrink renginio laiške.');
    end if;
    who := dname;
  end if;

  for c in select k.id, k.card_no, k.title, p.pin from public.uta_cards k left join public.uta_pins p on p.card_id = k.id
            where k.active and k.assign_kind = 'vehicle' and k.vehicle_id = vid order by k.created_at loop
    -- a member: written down only with the fill (uta_vehicle_pin_done)
    if not member then insert into public.uta_pin_views (token, event_name, card_id, ok, reason, driver_name, lat, lng, acc, vehicle)
    values (tok, ev, c.id, c.pin is not null, case when c.pin is null then 'PIN neįrašytas' end, left(who, 120), lat, lng, acc, vname); end if;
    out := out || jsonb_build_object('card', public.uta_card_mask(c.card_no), 'title', coalesce(c.title, ''), 'pin', c.pin);
  end loop;
  return jsonb_build_object('pins', out, 'name', who, 'member', member, 'code', case when member then null else cd end, 'event', ev, 'vehicle', vname);
end $$;
revoke all on function public.uta_vehicle_pin(text, text, jsonb) from public;
grant execute on function public.uta_vehicle_pin(text, text, jsonb) to anon, authenticated;

-- „Registruoti kuro pylimą“ pressed: the PIN view goes to the UTA reports with this fill (comment, photos)
create or replace function public.uta_vehicle_pin_done(p_token text, p_log uuid, p_loc jsonb default null)
returns integer language plpgsql security definer set search_path = public as $$
declare v jsonb; vid text; vname text; tok text; lg record; who text; ev text; n int := 0;
        d date := (now() at time zone 'Europe/Vilnius')::date; lat double precision; lng double precision; acc int; lc jsonb;
begin
  v := public.vehicle_by_token(p_token);
  if v is null then raise exception 'QR kodas nebegalioja.'; end if;
  vid := v ->> 'id'; tok := 'qr:' || vid; vname := public.vehicle_label(v ->> 'name', v ->> 'plate');
  select id, created_by_name, data into lg from public.vehicle_logs
   where id = p_log and vehicle_id = vid and kind = 'fuel' and data ->> 'via' = 'qr' and created_at > now() - interval '15 minutes';
  if lg.id is null then return 0; end if;
  if exists (select 1 from public.uta_pin_views where log_id = p_log) then return 0; end if;
  lc := coalesce(lg.data -> 'loc', p_loc);
  begin
    lat := (lc ->> 'lat')::double precision; lng := (lc ->> 'lng')::double precision; acc := round((lc ->> 'acc')::numeric)::int;
    if lat not between -90 and 90 or lng not between -180 and 180 then lat := null; lng := null; acc := null; end if;
  exception when others then lat := null; lng := null; acc := null; end;
  if auth.uid() is not null and public.is_approved() then
    who := public.my_name();
    select event_name into ev from public.vehicle_drivers where vehicle_id = vid and day between d - 1 and d + 1 order by abs(day - d) limit 1;
    insert into public.uta_pin_views (token, event_name, card_id, ok, reason, driver_name, lat, lng, acc, vehicle, log_id)
    select tok, ev, k.id, p.pin is not null, case when p.pin is null then 'PIN neįrašytas' end, left(who, 120), lat, lng, acc, vname, p_log
      from public.uta_cards k left join public.uta_pins p on p.card_id = k.id
     where k.active and k.assign_kind = 'vehicle' and k.vehicle_id = vid;
    get diagnostics n = row_count;
  else
    -- not a member: the PIN view (shown after the driver's code) gets this fill
    update public.uta_pin_views x set log_id = p_log
     where x.id in (select distinct on (card_id) id from public.uta_pin_views
                     where token = tok and ok and log_id is null and at > now() - interval '3 hours' order by card_id, at desc);
    get diagnostics n = row_count;
  end if;
  return n;
end $$;
revoke all on function public.uta_vehicle_pin_done(text, uuid, jsonb) from public;
grant execute on function public.uta_vehicle_pin_done(text, uuid, jsonb) to anon, authenticated;

-- Super Admin: test entries out of the UTA reports (and, if asked, their fill in the vehicle's history)
create or replace function public.uta_pin_views_delete(p_ids bigint[], p_with_log boolean default false)
returns integer language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if not public.is_super() then raise exception 'Tik Super Admin.'; end if;
  if p_with_log then
    delete from public.vehicle_logs where kind = 'fuel' and data ->> 'via' = 'qr'
       and id in (select log_id from public.uta_pin_views where id = any(p_ids) and log_id is not null);
  end if;
  delete from public.uta_pin_views where id = any(p_ids);
  get diagnostics n = row_count;
  return n;
end $$;
revoke all on function public.uta_pin_views_delete(bigint[], boolean) from public, anon;
grant execute on function public.uta_pin_views_delete(bigint[], boolean) to authenticated;

notify pgrst, 'reload schema';
