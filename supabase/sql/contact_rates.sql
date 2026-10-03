-- ============================================================
-- Žmonės (Bookingas / Archyvas): valandinis ir stafkė
--  * atskira lentelė, kad įkainių nematytų visi, kas mato „Žmones“
--    (kontaktų lentelę skaito visi su „Žmonių“ teise)
--  * mato ir keičia tik office, projektų vadovai (pm) ir admin
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.contact_rates (
  contact_id  text primary key references public.contacts(id) on delete cascade,
  hourly      numeric(10,2) check (hourly is null or (hourly >= 0 and hourly < 100000)),
  daily       numeric(10,2) check (daily is null or (daily >= 0 and daily < 1000000)),
  note        text,
  updated_at  timestamptz not null default now(),
  updated_by  uuid default auth.uid()
);

create or replace function public.rates_access() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role in ('admin','pm','office') from public.profiles where id = auth.uid()), false)
$$;
revoke all on function public.rates_access() from public, anon;
grant execute on function public.rates_access() to authenticated;

alter table public.contact_rates enable row level security;
drop policy if exists "rates view" on public.contact_rates;
create policy "rates view" on public.contact_rates for select to authenticated using (public.rates_access());
drop policy if exists "rates change" on public.contact_rates;
create policy "rates change" on public.contact_rates for all to authenticated
  using (public.rates_access()) with check (public.rates_access());
revoke all on public.contact_rates from anon;
grant select, insert, update, delete on public.contact_rates to authenticated;

create or replace function public.contact_rates_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  new.updated_at := now();
  if auth.uid() is not null then new.updated_by := auth.uid(); end if;
  return new;
end $$;
drop trigger if exists contact_rates_stamp on public.contact_rates;
create trigger contact_rates_stamp before insert or update on public.contact_rates
  for each row execute function public.contact_rates_stamp();
