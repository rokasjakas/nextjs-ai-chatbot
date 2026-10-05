-- ============================================================
-- „Išlaidos“: kuro, maisto ir kitos nario išlaidos su kvitais
--  * expenses      – kiekviena išlaida (kas, kada, kam, kiek, UTA ar savi pinigai, kvitai);
--                    mėnesio gale Admin / Office / Projektų vadovas patvirtina ir priskiria kompensaciją
--  * uta_personal  – UTA kortelės pylimai, pažymėti kaip asmeniniai (iš sukauptos kompensacijos)
--  * expense-files – kvitų nuotraukos / failai (<nario id>/<išlaidos id>/<failas>)
-- Narys mato ir rašo savo; Admin / Office / Projektų vadovas – visų.
-- Narys taip pat mato savo (jam priskirtos) UTA kortelės pylimus.
-- Reikia: purchases.sql (buy_manager) ir uta.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.expenses (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null default auth.uid() references auth.users(id) on delete cascade,
  user_name     text,
  kind          text not null check (kind in ('fuel','food','other')),
  spent_on      date not null,
  route         text not null default '',
  reason        text not null default '',
  liters        numeric(10,2),
  amount        numeric(12,2),
  paid          text not null default 'own' check (paid in ('uta','own')),
  uta_tx_id     uuid references public.uta_tx(id) on delete set null,
  receipts      jsonb not null default '[]'::jsonb,
  status        text not null default 'new' check (status in ('new','ok','rejected')),
  comp          numeric(12,2),
  review_note   text,
  reviewed_by   uuid,
  reviewed_name text,
  reviewed_at   timestamptz,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create index if not exists expenses_user_date on public.expenses (user_id, spent_on);
create index if not exists expenses_date on public.expenses (spent_on);

create table if not exists public.uta_personal (
  tx_id      uuid primary key references public.uta_tx(id) on delete cascade,
  user_id    uuid not null references auth.users(id) on delete cascade,
  marked_by  uuid default auth.uid(),
  created_at timestamptz not null default now()
);

-- the fill is on a UTA card given to this member
create or replace function public.uta_tx_mine(tx uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.uta_tx t join public.uta_cards c on c.id = t.card_id
                 where t.id = tx and c.assign_kind = 'person' and c.person_id = auth.uid())
$$;
grant execute on function public.uta_tx_mine(uuid) to authenticated;

alter table public.expenses enable row level security;
alter table public.uta_personal enable row level security;

drop policy if exists "expenses view" on public.expenses;
create policy "expenses view" on public.expenses for select to authenticated
  using (user_id = auth.uid() or public.buy_manager());
drop policy if exists "expenses add" on public.expenses;
create policy "expenses add" on public.expenses for insert to authenticated
  with check (user_id = auth.uid() and public.is_approved() and status = 'new' and comp is null);
-- the member changes / removes own ones until they are checked; the managers always
drop policy if exists "expenses edit" on public.expenses;
create policy "expenses edit" on public.expenses for update to authenticated
  using (public.buy_manager() or (user_id = auth.uid() and status = 'new'))
  with check (public.buy_manager() or (user_id = auth.uid() and status = 'new' and comp is null));
drop policy if exists "expenses remove" on public.expenses;
create policy "expenses remove" on public.expenses for delete to authenticated
  using (public.buy_manager() or (user_id = auth.uid() and status = 'new'));

drop policy if exists "uta personal view" on public.uta_personal;
create policy "uta personal view" on public.uta_personal for select to authenticated
  using (user_id = auth.uid() or public.buy_manager());
drop policy if exists "uta personal add" on public.uta_personal;
create policy "uta personal add" on public.uta_personal for insert to authenticated
  with check (public.buy_manager() or (user_id = auth.uid() and public.uta_tx_mine(tx_id)));
drop policy if exists "uta personal remove" on public.uta_personal;
create policy "uta personal remove" on public.uta_personal for delete to authenticated
  using (public.buy_manager() or user_id = auth.uid());

-- the member sees the UTA card(s) given to them and their fills (besides who sees „Transportas“)
drop policy if exists "uta cards own" on public.uta_cards;
create policy "uta cards own" on public.uta_cards for select to authenticated
  using (assign_kind = 'person' and person_id = auth.uid());
drop policy if exists "uta tx own" on public.uta_tx;
create policy "uta tx own" on public.uta_tx for select to authenticated
  using (public.uta_tx_mine(id));
-- managers check everyone's fills at month end
drop policy if exists "uta cards managers" on public.uta_cards;
create policy "uta cards managers" on public.uta_cards for select to authenticated using (public.buy_manager());
drop policy if exists "uta tx managers" on public.uta_tx;
create policy "uta tx managers" on public.uta_tx for select to authenticated using (public.buy_manager());

revoke all on public.expenses, public.uta_personal from anon;
grant select, insert, update, delete on public.expenses, public.uta_personal to authenticated;

-- receipts: <member>/<expense>/<file>; the member and the managers read, the member adds, both remove
insert into storage.buckets (id, name, public) values ('expense-files', 'expense-files', false) on conflict (id) do nothing;
drop policy if exists "expense files read" on storage.objects;
create policy "expense files read" on storage.objects for select to authenticated
  using (bucket_id = 'expense-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.buy_manager()));
drop policy if exists "expense files add" on storage.objects;
create policy "expense files add" on storage.objects for insert to authenticated
  with check (bucket_id = 'expense-files' and (storage.foldername(name))[1] = auth.uid()::text and public.is_approved());
drop policy if exists "expense files remove" on storage.objects;
create policy "expense files remove" on storage.objects for delete to authenticated
  using (bucket_id = 'expense-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.buy_manager()));

notify pgrst, 'reload schema';
