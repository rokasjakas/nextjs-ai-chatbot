-- Paėmimai: laikinos nuorodos (48 val.) – be paskyros, įvedus vardą ir pavardę, galima matyti paėmimus, pažymėti paėmimą
-- ir grąžinimą, įkelti nuotraukas ir pranešti apie trūkstamus daiktus (serverio funkcija rentals-guest).
-- Saugoma tik nuorodos rakto santrauka (sha256). Lentelę skaito ir rašo tik serverio funkcija. Saugu paleisti pakartotinai.
create table if not exists public.rental_links (
  id              uuid primary key default gen_random_uuid(),
  token_hash      text not null unique,
  created_by      uuid,
  created_by_name text not null default '',
  created_at      timestamptz not null default now(),
  expires_at      timestamptz not null,
  revoked_at      timestamptz,
  opened          jsonb not null default '[]'::jsonb      -- [{name, at}] kas atidarė
);
create index if not exists rental_links_exp_idx on public.rental_links (expires_at);
alter table public.rental_links enable row level security;
revoke all on public.rental_links from anon, authenticated;
notify pgrst, 'reload schema';
select 'rental_links' as k, count(*)::text as v from public.rental_links;
