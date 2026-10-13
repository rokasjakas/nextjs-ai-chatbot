-- ============================================================
-- „Išlaidos“ → „Narių išlaidos“: „Nurašyti nuo balanso“
-- Darbo išlaida, kurios nepavyksta pagrįsti (nėra kvito, neįrašyta, kokiam renginiui…): Office ir aukštesni
-- (kuro išlaidas) ar Admin+ (kitas) nurašo ją nuo nario balanso su paaiškinimu –
--  * su UTA pylimu susieta – tas pylimas tampa asmeniniu (uta_personal, su pastaba ir kvitais);
--  * kita (savais pinigais, iš savo kuro) – įrašas „nurašyta nuo balanso“ (comp_use) nurodyta suma.
-- Išlaida pažymima kaip asmeninė, patvirtinta, su paaiškinimu; narys gauna pranešimą.
-- Office+ kuro išlaidai gali ir „Prašyti paaiškinti“.
-- Reikia: expenses_review.sql, comp_use.sql, expenses_rules.sql, expenses_purpose.sql. Saugu paleisti pakartotinai.
-- ============================================================

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
    insert into public.comp_use (user_id, used_on, unit, amount, liters, note, created_by)
    values (e.user_id, e.spent_on, 'eur', round(amt, 2), e.liters, left('Nurašyta nuo balanso: ' || coalesce(nullif(e.reason, ''), 'išlaida') || ' – ' || trim(p_note), 500), auth.uid());
  end if;
  update public.expenses set purpose = 'personal', status = 'ok', comp = null,
         review_note = left('Nurašyta nuo balanso: ' || trim(p_note), 1000), reviewed_by = auth.uid(), reviewed_name = who, reviewed_at = now()
   where id = p_id;
  return jsonb_build_object('amount', amt, 'uta', e.uta_tx_id is not null);
end $$;
revoke all on function public.expense_deduct(uuid, text, numeric) from public, anon;
grant execute on function public.expense_deduct(uuid, text, numeric) to authenticated;

-- Office+ may also ask to explain a fuel expense; the history marks the deduction
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
              else new.status end;
  if act = 'resubmit' then new.resubmitted_at := now(); end if;
  new.review_log := coalesce(old.review_log, '[]'::jsonb) || jsonb_build_object('at', now(), 'by', coalesce(auth.uid(), new.reviewed_by), 'name', who, 'act', act,
    'note', case when act in ('fix','info','rejected','ok','paid','deduct') then new.review_note end,
    'comp', case when new.comp is distinct from old.comp then new.comp end);
  return new;
end $$;

notify pgrst, 'reload schema';
