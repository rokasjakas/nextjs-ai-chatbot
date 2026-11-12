-- ============================================================
-- „Išlaidos“ → „Narių išlaidos“: „Nurašyti nuo balanso“
-- Darbo išlaida, kurios nepavyksta pagrįsti (nėra kvito, neįrašyta, kokiam renginiui…): Office ir aukštesni
-- (kuro išlaidas) ar Admin+ (kitas) nurašo ją nuo nario balanso su paaiškinimu –
--  * su UTA pylimu susieta – tas pylimas tampa asmeniniu (uta_personal, su pastaba ir kvitais);
--  * kita (savais pinigais, iš savo kuro) – įrašas „nurašyta nuo balanso“ (comp_use) nurodyta suma.
-- „Darbo reikalais“ / „Asmeninis“ (expense_set_purpose): Office+ pakeičia kuro išlaidos tikslą, jei narys
-- pažymėjo neteisingai. Asmeninis – UTA pylimas atimamas iš balanso (nesant balanso ar jam pasibaigus –
-- minusas); darbo – nieko neatimama, anksčiau nurašyta grąžinama.
-- Išlaida pažymima kaip asmeninė, patvirtinta, su paaiškinimu; narys gauna pranešimą.
-- Office+ kuro išlaidai gali ir „Prašyti paaiškinti“.
-- Reikia: expenses_review.sql, comp_use.sql, expenses_rules.sql, expenses_purpose.sql. Saugu paleisti pakartotinai.
-- ============================================================

-- a deduction of an expense not tied to a UTA fill: which expense it was
alter table public.comp_use add column if not exists expense_id uuid references public.expenses(id) on delete cascade;
create index if not exists comp_use_expense on public.comp_use (expense_id);

create or replace function public.expense_deduct(p_id uuid, p_note text, p_amount numeric default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare e public.expenses; amt numeric; who text;
begin
  select * into e from public.expenses where id = p_id for update;
  if e.id is null then raise exception 'Išlaida nerasta.'; end if;
  if not (public.is_plus() or (e.kind = 'fuel' and public.exp_fuel_checker())) then raise exception 'Nėra teisės.'; end if;
  if length(trim(coalesce(p_note, ''))) < 3 then raise exception 'Parašyk paaiškinimą.'; end if;
  select coalesce(nullif(trim(concat_ws(' ', first_name, last_name)), ''), email) into who from public.profiles where id = auth.uid();
  if e.uta_tx_id is not null then
    insert into public.uta_personal (tx_id, user_id, receipts, note, unit)
    values (e.uta_tx_id, e.user_id, coalesce(e.receipts, '[]'::jsonb), left('Nurašyta nuo balanso: ' || trim(p_note), 500), 'eur')
    on conflict (tx_id) do update set note = excluded.note;
    select amount_gross into amt from public.uta_tx where id = e.uta_tx_id;
  else
    amt := coalesce(p_amount, e.amount);
    if amt is null or amt <= 0 then raise exception 'Nurodyk sumą eurais.'; end if;
    delete from public.comp_use where expense_id = e.id;
    insert into public.comp_use (user_id, used_on, unit, amount, liters, note, created_by, expense_id)
    values (e.user_id, e.spent_on, 'eur', round(amt, 2), e.liters, left('Nurašyta nuo balanso: ' || coalesce(nullif(e.reason, ''), 'išlaida') || ' – ' || trim(p_note), 500), auth.uid(), e.id);
  end if;
  update public.expenses set purpose = 'personal', status = 'ok', comp = null,
         review_note = left('Nurašyta nuo balanso: ' || trim(p_note), 1000), reviewed_by = auth.uid(), reviewed_name = who, reviewed_at = now()
   where id = p_id;
  return jsonb_build_object('amount', amt, 'uta', e.uta_tx_id is not null);
end $$;
revoke all on function public.expense_deduct(uuid, text, numeric) from public, anon;
grant execute on function public.expense_deduct(uuid, text, numeric) to authenticated;

-- „Darbo reikalais“ / „Asmeninis“: the purpose of a fuel expense set by who checks it
create or replace function public.expense_set_purpose(p_id uuid, p_purpose text, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare e public.expenses; who text; tx uuid; amt numeric; n int; how text := '';
begin
  select * into e from public.expenses where id = p_id for update;
  if e.id is null then raise exception 'Išlaida nerasta.'; end if;
  if not (public.is_plus() or (e.kind = 'fuel' and public.exp_fuel_checker())) then raise exception 'Nėra teisės.'; end if;
  if e.kind <> 'fuel' then raise exception 'Tikslas keičiamas tik kuro išlaidai.'; end if;
  if p_purpose not in ('work','personal') then raise exception 'Netinkamas tikslas.'; end if;
  select coalesce(nullif(trim(concat_ws(' ', first_name, last_name)), ''), email) into who from public.profiles where id = auth.uid();
  tx := e.uta_tx_id;
  if p_purpose = 'personal' then
    -- paid with the UTA card but not tied to a fill: that day's only fill of the member's card
    if tx is null and e.paid = 'uta' then
      select count(*), min(t.id::text)::uuid into n, tx from public.uta_tx t join public.uta_cards c on c.id = t.card_id
       where c.assign_kind = 'person' and c.person_id = e.user_id and t.tx_date = e.spent_on and coalesce(t.quantity, 0) > 0;
      if n <> 1 then tx := null; end if;
    end if;
    if tx is not null then
      insert into public.uta_personal (tx_id, user_id, receipts, note, unit)
      values (tx, e.user_id, coalesce(e.receipts, '[]'::jsonb), left('Asmeninis (pakeitė ' || coalesce(who, '') || ')' || coalesce(': ' || nullif(trim(p_note), ''), ''), 500), 'eur')
      on conflict (tx_id) do update set note = excluded.note;
      select amount_gross into amt from public.uta_tx where id = tx;
      how := 'uta';
    elsif e.paid = 'uta' then
      amt := e.amount;
      if amt is not null and amt > 0 then
        delete from public.comp_use where expense_id = e.id;
        insert into public.comp_use (user_id, used_on, unit, amount, liters, note, created_by, expense_id)
        values (e.user_id, e.spent_on, 'eur', round(amt, 2), e.liters, left('Asmeninis UTA pylimas (pakeitė ' || coalesce(who, '') || ')', 500), auth.uid(), e.id);
        how := 'sum';
      else how := 'nofill'; end if;
    else how := 'own'; end if;   -- paid with own money / own fuel: the company paid nothing, nothing to take
  else
    -- work: what was taken for it goes back
    if tx is not null then delete from public.uta_personal where tx_id = tx; end if;
    delete from public.comp_use where expense_id = e.id
       or (expense_id is null and user_id = e.user_id and used_on = e.spent_on and note like 'Nurašyta nuo balanso: %');   -- made before expense_id
    how := 'work';
  end if;
  update public.expenses set purpose = p_purpose, uta_tx_id = coalesce(e.uta_tx_id, case when how = 'uta' then tx end), status = 'ok', comp = null,
         review_note = left('Tikslas pakeistas: ' || case when p_purpose = 'work' then 'darbo reikalais' else 'asmeninis' end || coalesce(' – ' || nullif(trim(p_note), ''), ''), 1000),
         reviewed_by = auth.uid(), reviewed_name = who, reviewed_at = now()
   where id = p_id;
  return jsonb_build_object('how', how, 'amount', amt);
end $$;
revoke all on function public.expense_set_purpose(uuid, text, text) from public, anon;
grant execute on function public.expense_set_purpose(uuid, text, text) to authenticated;

-- Office+ may also ask to explain a fuel expense; the history marks the deduction and the purpose
create or replace function public.expenses_review_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or public.is_plus() then return new; end if;   -- the server (push-notify „Apmokėti“) or Admin+
  if new.status is distinct from old.status or new.comp is distinct from old.comp or new.comp_unit is distinct from old.comp_unit
     or new.review_note is distinct from old.review_note or new.paid_at is distinct from old.paid_at or new.paid_to is distinct from old.paid_to then
    if new.user_id = auth.uid() and new.status = 'new' and new.comp is null and new.paid_at is null then return new; end if;
    if old.kind = 'fuel' and new.kind = 'fuel' and public.exp_fuel_checker() and new.status in ('ok','fix','info','new')
       and new.comp is not distinct from old.comp and new.comp_unit is not distinct from old.comp_unit
       and new.paid_at is not distinct from old.paid_at and new.paid_to is not distinct from old.paid_to then return new; end if;
    raise exception 'Šio sprendimo priimti negali – kuro išlaidas tvirtina Office+, kitas ir kompensacijas – Admin+ narys.';
  end if;
  return new;
end $$;
create or replace function public.expenses_review_trail() returns trigger
  language plpgsql security definer set search_path = public as $$
declare who text; act text;
begin
  if new.status is not distinct from old.status and new.review_note is not distinct from old.review_note and new.comp is not distinct from old.comp then return new; end if;
  select coalesce(nullif(trim(concat_ws(' ', first_name, last_name)), ''), email) into who from public.profiles where id = auth.uid();
  if who is null then who := new.reviewed_name; end if;
  act := case when new.status = 'new' and old.status in ('fix','info','rejected') and new.user_id = auth.uid() then 'resubmit'
              when new.status = 'new' and new.user_id = auth.uid() then 'edit'
              when new.review_note like 'Nurašyta nuo balanso:%' and new.review_note is distinct from old.review_note then 'deduct'
              when new.review_note like 'Tikslas pakeistas:%' and new.review_note is distinct from old.review_note then 'purpose'
              else new.status end;
  if act = 'resubmit' then new.resubmitted_at := now(); end if;
  new.review_log := coalesce(old.review_log, '[]'::jsonb) || jsonb_build_object('at', now(), 'by', coalesce(auth.uid(), new.reviewed_by), 'name', who, 'act', act,
    'note', case when act in ('fix','info','rejected','ok','paid','deduct','purpose') then new.review_note end,
    'comp', case when new.comp is distinct from old.comp then new.comp end);
  return new;
end $$;

notify pgrst, 'reload schema';
