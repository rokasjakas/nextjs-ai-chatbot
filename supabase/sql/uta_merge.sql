-- ============================================================
-- UTA kortelių dublikatų sujungimas
-- Naujos UTA ataskaitos („Detali specifikacija“) kortelės numerį rašo su kontroliniu skaitmeniu
-- (706000 949837 0046 9), senosios – be jo (…0046). Tai ta pati kortelė: p_drop sujungiama į p_keep –
-- pylimai, PIN, priskyrimas (jei p_keep nepriskirta), pavadinimas; tie patys pylimai (ta pati diena,
-- kiekis ir suma) iš abiejų ataskaitų lieka vieną kartą. p_keep gauna pilną (ilgesnį) numerį.
-- Reikia: uta.sql, uta_pins.sql. Saugu paleisti pakartotinai.
-- ============================================================

-- the work itself (no rights check: called by the RPC below and by this script)
create or replace function public.uta_cards_merge_do(p_keep uuid, p_drop uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare k public.uta_cards; d public.uta_cards; moved int := 0; dups int := 0; no text;
begin
  if p_keep = p_drop then raise exception 'same card'; end if;
  select * into k from public.uta_cards where id = p_keep for update;
  select * into d from public.uta_cards where id = p_drop for update;
  if k.id is null or d.id is null then raise exception 'card not found'; end if;

  -- the same fill in both reports (old and new format): the one already there stays
  with x as (
    delete from public.uta_tx t
     where t.card_id = p_drop
       and exists (select 1 from public.uta_tx o
                    where o.card_id = p_keep and o.tx_date = t.tx_date
                      and round(coalesce(o.quantity, 0), 2) = round(coalesce(t.quantity, 0), 2)
                      and round(coalesce(o.amount_gross, o.amount_net, 0), 2) = round(coalesce(t.amount_gross, t.amount_net, 0), 2)
                      and lower(coalesce(o.product, '')) = lower(coalesce(t.product, '')))
    returning 1)
  select count(*) into dups from x;
  update public.uta_tx set card_id = p_keep where card_id = p_drop;
  get diagnostics moved = row_count;

  -- PIN: the kept card's own, else the other's
  if exists (select 1 from public.uta_pins where card_id = p_drop) and not exists (select 1 from public.uta_pins where card_id = p_keep) then
    update public.uta_pins set card_id = p_keep where card_id = p_drop;
  end if;

  no := case when length(regexp_replace(d.card_no, '[^0-9]', '', 'g')) > length(regexp_replace(k.card_no, '[^0-9]', '', 'g')) then d.card_no else k.card_no end;
  delete from public.uta_cards where id = p_drop;
  update public.uta_cards set
    card_no      = no,
    title        = case when coalesce(k.title, '') = '' then d.title else k.title end,
    assign_kind  = case when k.assign_kind = 'none' then d.assign_kind else k.assign_kind end,
    vehicle_id   = case when k.assign_kind = 'none' then d.vehicle_id else k.vehicle_id end,
    vehicle_name = case when k.assign_kind = 'none' then d.vehicle_name else k.vehicle_name end,
    person_id    = case when k.assign_kind = 'none' then d.person_id else k.person_id end,
    person_name  = case when k.assign_kind = 'none' then d.person_name else k.person_name end,
    valid_until  = coalesce(k.valid_until, d.valid_until),
    shared       = k.shared or d.shared,
    active       = k.active or d.active,
    updated_at   = now()
  where id = p_keep;
  return jsonb_build_object('moved', moved, 'duplicates', dups, 'card_no', no);
end $$;
revoke all on function public.uta_cards_merge_do(uuid, uuid) from public, anon, authenticated;

create or replace function public.uta_cards_merge(p_keep uuid, p_drop uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  if not public.can_edit('fleet') then raise exception 'not allowed'; end if;
  return public.uta_cards_merge_do(p_keep, p_drop);
end $$;
revoke all on function public.uta_cards_merge(uuid, uuid) from public, anon;
grant execute on function public.uta_cards_merge(uuid, uuid) to authenticated;

-- all such pairs now: one number is the other plus the last check digit; the card given to someone
-- (or the older one) stays
do $$
declare r record; n int := 0;
begin
  for r in
    select distinct on (least(a.id::text, b.id::text), greatest(a.id::text, b.id::text))
           case when (a.assign_kind <> 'none') <> (b.assign_kind <> 'none') then case when a.assign_kind <> 'none' then a.id else b.id end
                when a.created_at <= b.created_at then a.id else b.id end as keep,
           case when (a.assign_kind <> 'none') <> (b.assign_kind <> 'none') then case when a.assign_kind <> 'none' then b.id else a.id end
                when a.created_at <= b.created_at then b.id else a.id end as drop
      from public.uta_cards a
      join public.uta_cards b on a.id <> b.id
       and length(regexp_replace(a.card_no, '[^0-9]', '', 'g')) >= 12
       and length(regexp_replace(b.card_no, '[^0-9]', '', 'g')) = length(regexp_replace(a.card_no, '[^0-9]', '', 'g')) + 1
       and left(regexp_replace(b.card_no, '[^0-9]', '', 'g'), length(regexp_replace(a.card_no, '[^0-9]', '', 'g'))) = regexp_replace(a.card_no, '[^0-9]', '', 'g')
  loop
    if exists (select 1 from public.uta_cards where id = r.keep) and exists (select 1 from public.uta_cards where id = r.drop) then
      perform public.uta_cards_merge_do(r.keep, r.drop); n := n + 1;
    end if;
  end loop;
  raise notice 'UTA kortelių sujungta: %', n;
end $$;

notify pgrst, 'reload schema';
