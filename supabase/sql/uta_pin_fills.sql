-- ============================================================
-- „Kuro kortelė“ → UTA pylimas
-- Vairuotojas telefone nurašo skaičius po „CVC:“ ir pamato PIN – tai įvykis (uta_pin_views).
-- Įkėlus UTA ataskaitą jis susiejamas su tos kortelės pylimu (uta_pin_views.tx_id):
--  * ataskaitoje su laiku – artimiausias pylimas nuo 3 val. prieš (nariui įrašoma užregistravus pylimą,
--    t. y. jau po jo) iki 6 val. po PIN peržiūros;
--  * ataskaitoje be laiko (PDF) – tos pačios dienos (ar kitos dienos, jei PIN žiūrėtas vakare) pylimas.
-- Kelios to paties žmogaus peržiūros per 2 val. – tas pats pylimas. Ištrynus ataskaitą ryšys dingsta,
-- įkėlus vėl – susiejama iš naujo. Nesusietos peržiūros rodomos UTA puslapyje ir Ataskaitose.
-- Reikia: uta.sql, uta_pin_links.sql. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.uta_pin_views add column if not exists tx_id uuid references public.uta_tx(id) on delete set null;
create index if not exists uta_pin_views_tx on public.uta_pin_views (tx_id);

-- the work: every PIN view not yet joined to a fill (last 400 days)
create or replace function public.uta_pin_link_fills_do()
returns integer language plpgsql security definer set search_path = public as $$
declare v record; t uuid; n int := 0;
begin
  for v in select id, card_id, at, driver_name from public.uta_pin_views
            where ok and card_id is not null and tx_id is null and at > now() - interval '400 days'
            order by at loop
    -- the same person's view of the same card a little earlier: the same fill
    select p.tx_id into t from public.uta_pin_views p
     where p.card_id = v.card_id and p.tx_id is not null and p.id <> v.id
       and p.at between v.at - interval '2 hours' and v.at
       and lower(coalesce(p.driver_name, '')) = lower(coalesce(v.driver_name, ''))
     order by p.at desc limit 1;
    if t is null then
      select x.id into t from public.uta_tx x
       where x.card_id = v.card_id and coalesce(x.quantity, 0) > 0
         and not exists (select 1 from public.uta_pin_views o where o.tx_id = x.id and abs(extract(epoch from o.at - v.at)) > 7200)
         and (case when (x.tx_at at time zone 'Europe/Vilnius')::time <> '00:00'
                   then x.tx_at between v.at - interval '3 hours' and v.at + interval '6 hours'
                   else x.tx_date = (v.at at time zone 'Europe/Vilnius')::date
                     or (x.tx_date = (v.at at time zone 'Europe/Vilnius')::date + 1 and (v.at at time zone 'Europe/Vilnius')::time >= '18:00') end)
       order by case when (x.tx_at at time zone 'Europe/Vilnius')::time <> '00:00' then abs(extract(epoch from x.tx_at - v.at)) else 0 end,
                (x.tx_date <> (v.at at time zone 'Europe/Vilnius')::date), x.tx_at, x.id
       limit 1;
    end if;
    if t is not null then update public.uta_pin_views set tx_id = t where id = v.id; n := n + 1; end if;
  end loop;
  return n;
end $$;
revoke all on function public.uta_pin_link_fills_do() from public, anon, authenticated;

-- after a report is loaded (or a fill moved to another card): joined by itself
create or replace function public.uta_pin_link_fills_trg() returns trigger
  language plpgsql security definer set search_path = public as $$
begin perform public.uta_pin_link_fills_do(); return null; end $$;
drop trigger if exists uta_pin_link_fills on public.uta_tx;
create trigger uta_pin_link_fills after insert or update of card_id on public.uta_tx
  for each statement execute function public.uta_pin_link_fills_trg();

-- the page asks after an upload: how many joined, how many views of that time have no fill
create or replace function public.uta_pin_link_fills(p_from date default null, p_to date default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare n int; last date; ok int; open int;
begin
  if not public.can_view('fleet') then raise exception 'not allowed'; end if;
  n := public.uta_pin_link_fills_do();
  select max(tx_date) into last from public.uta_tx;
  select count(*) filter (where v.tx_id is not null),
         count(*) filter (where v.tx_id is null and (v.at at time zone 'Europe/Vilnius')::date <= coalesce(last, '1900-01-01'))
    into ok, open
    from public.uta_pin_views v
   where v.ok
     and (p_from is null or (v.at at time zone 'Europe/Vilnius')::date >= p_from)
     and (p_to is null or (v.at at time zone 'Europe/Vilnius')::date <= p_to);
  return jsonb_build_object('linked', ok, 'unlinked', open, 'new', n, 'last', last);
end $$;
revoke all on function public.uta_pin_link_fills(date, date) from public, anon;
grant execute on function public.uta_pin_link_fills(date, date) to authenticated;

-- cards joined (uta_merge.sql): their PIN views go along
create or replace function public.uta_pin_views_card_move() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if new.card_id is distinct from old.card_id and old.card_id is not null and new.card_id is not null
     and not exists (select 1 from public.uta_tx where card_id = old.card_id) then
    update public.uta_pin_views set card_id = new.card_id where card_id = old.card_id;
  end if;
  return null;
end $$;
drop trigger if exists uta_pin_views_card_move on public.uta_tx;
create trigger uta_pin_views_card_move after update of card_id on public.uta_tx
  for each row execute function public.uta_pin_views_card_move();

-- the views loaded so far
select public.uta_pin_link_fills_do();

notify pgrst, 'reload schema';
