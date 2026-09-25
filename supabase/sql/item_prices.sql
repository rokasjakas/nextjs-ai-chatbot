-- ============================================================
-- Sandėlis: daiktų kainos. Mato ir keičia tik administratoriai ir
-- projektų vadovai (lygis „pm“) – kitiems lygiams duomenų bazė jų neduoda.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.item_prices (
  item_id    text primary key,
  price      numeric(12,2),
  updated_at timestamptz not null default now(),
  updated_by text
);
alter table public.item_prices enable row level security;
drop policy if exists "prices admin and pm" on public.item_prices;
create policy "prices admin and pm" on public.item_prices
  for all to authenticated
  using (public.is_admin() or coalesce(public.my_role(), '') = 'pm')
  with check (public.is_admin() or coalesce(public.my_role(), '') = 'pm');
grant select, insert, update, delete on public.item_prices to authenticated;
