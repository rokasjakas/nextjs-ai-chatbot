-- ============================================================
-- „Išlaidos“ → „Narių išlaidos“: patikra su korekcijomis
--  * kuro išlaidas mato ir tikrina Office ir aukštesnio lygio nariai (Office, Projektų vadovas, Admin):
--    „Patvirtinti“ arba „Koreguoti“ (komentaras, ko trūksta) – narys gauna pranešimą, pataiso ir
--    pateikia vėl, korekcijų paprašęs narys gauna pranešimą; taip iki patvirtinimo
--  * kitas išlaidas (maistas, kitos) mato tik jas pateikęs narys ir Admin+ narys; Admin+ gali:
--    priskirti balansui (kompensacija), apmokėti (laiškas buhalterijai – status 'paid'),
--    prašyti daugiau paaiškinti ('info') arba atmesti su komentaru
--  * review_log – kas, kada ir ką nusprendė / paprašė (istorija išlaidos lange)
-- Reikia: expenses.sql, expenses_rules.sql (is_plus), expenses_liters.sql, purchases.sql (buy_manager).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.expenses drop constraint if exists expenses_status_check;
alter table public.expenses add constraint expenses_status_check check (status in ('new','ok','rejected','fix','info','paid'));
alter table public.expenses add column if not exists review_log jsonb not null default '[]'::jsonb;
alter table public.expenses add column if not exists resubmitted_at timestamptz;
alter table public.expenses add column if not exists paid_at timestamptz;
alter table public.expenses add column if not exists paid_to text[];

-- Office and higher (who checks fuel expenses)
create or replace function public.exp_fuel_checker() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','office','pm'), false)
$$;
grant execute on function public.exp_fuel_checker() to authenticated;

-- fuel: the member and Office+; other expenses: only the member and Admin+
drop policy if exists "expenses view" on public.expenses;
create policy "expenses view" on public.expenses for select to authenticated
  using (user_id = auth.uid() or public.is_plus() or (kind = 'fuel' and public.exp_fuel_checker()));
drop policy if exists "expenses edit" on public.expenses;
create policy "expenses edit" on public.expenses for update to authenticated
  using (public.is_plus() or (kind = 'fuel' and public.exp_fuel_checker()) or (user_id = auth.uid() and public.exp_month_open(spent_on)))
  with check (public.is_plus() or (kind = 'fuel' and public.exp_fuel_checker()) or (user_id = auth.uid() and status = 'new' and comp is null and public.exp_month_open(spent_on)));
drop policy if exists "expenses remove" on public.expenses;
create policy "expenses remove" on public.expenses for delete to authenticated
  using (public.is_plus() or (user_id = auth.uid() and public.exp_month_open(spent_on)));

-- deciding: Admin+ anything; Office+ a fuel expense's „Patvirtinti“ / „Koreguoti“ (not the compensation);
-- the member correcting an own expense sends it back to „waits“
create or replace function public.expenses_review_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or public.is_plus() then return new; end if;   -- the server (push-notify „Apmokėti“) or Admin+
  if new.status is distinct from old.status or new.comp is distinct from old.comp or new.comp_unit is distinct from old.comp_unit
     or new.review_note is distinct from old.review_note or new.paid_at is distinct from old.paid_at or new.paid_to is distinct from old.paid_to then
    if new.user_id = auth.uid() and new.status = 'new' and new.comp is null and new.paid_at is null then return new; end if;
    if old.kind = 'fuel' and new.kind = 'fuel' and public.exp_fuel_checker() and new.status in ('ok','fix','new')
       and new.comp is not distinct from old.comp and new.comp_unit is not distinct from old.comp_unit
       and new.paid_at is not distinct from old.paid_at and new.paid_to is not distinct from old.paid_to then return new; end if;
    raise exception 'Šio sprendimo priimti negali – kuro išlaidas tvirtina Office+, kitas ir kompensacijas – Admin+ narys.';
  end if;
  return new;
end $$;
drop trigger if exists expenses_review_guard on public.expenses;
create trigger expenses_review_guard before update on public.expenses for each row execute function public.expenses_review_guard();

-- the history: every decision and every resubmission written down by itself
create or replace function public.expenses_review_trail() returns trigger
  language plpgsql security definer set search_path = public as $$
declare who text; act text;
begin
  if new.status is not distinct from old.status and new.review_note is not distinct from old.review_note and new.comp is not distinct from old.comp then return new; end if;
  select coalesce(nullif(trim(concat_ws(' ', first_name, last_name)), ''), email) into who from public.profiles where id = auth.uid();
  if who is null then who := new.reviewed_name; end if;
  act := case when new.status = 'new' and old.status in ('fix','info','rejected') and new.user_id = auth.uid() then 'resubmit'
              when new.status = 'new' and new.user_id = auth.uid() then 'edit'
              else new.status end;
  if act = 'resubmit' then new.resubmitted_at := now(); end if;
  new.review_log := coalesce(old.review_log, '[]'::jsonb) || jsonb_build_object('at', now(), 'by', coalesce(auth.uid(), new.reviewed_by), 'name', who, 'act', act,
    'note', case when act in ('fix','info','rejected','ok','paid') then new.review_note end,
    'comp', case when new.comp is distinct from old.comp then new.comp end);
  return new;
end $$;
drop trigger if exists expenses_review_trail on public.expenses;
create trigger expenses_review_trail before update on public.expenses for each row execute function public.expenses_review_trail();

notify pgrst, 'reload schema';
