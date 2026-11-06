-- Freelancerių portalas: sąskaita sukuriama puslapyje – žmogaus rekvizitai (pardavėjas) ir paskutinis numeris
-- išsaugomi kitam kartui. Skaito ir rašo tik serverio funkcija (freelance-portal).
create table if not exists public.fl_portal_profiles (
  email        text primary key,
  seller       jsonb not null default '{}'::jsonb,   -- {kind, name, code, address, vat, iban, bank, email, phone}
  last_series  text,
  last_number  text,
  updated_at   timestamptz not null default now()
);
alter table public.fl_portal_profiles enable row level security;   -- no policies: only the server
revoke all on public.fl_portal_profiles from anon, authenticated;
notify pgrst, 'reload schema';
select 'fl_portal_profiles' as k, count(*)::text as v from public.fl_portal_profiles;
