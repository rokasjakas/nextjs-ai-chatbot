-- ============================================================
-- Freelancerių sąskaitos: saskaitos.eventsolutions.lt
--  * freelanceris įveda el. paštą → gauna vienkartinį PIN (galioja 1 val.) → užpildo,
--    kuriuose renginiuose dirbo (sutarta suma arba valandinis), įkelia sąskaitą;
--    sumos sulyginamos ir sąskaita atsiranda „Sąskaitose“ → Freelance su išskaidymu
--  * fl_portal_pins / fl_portal_sessions – tik serverio funkcijai „freelance-portal“
--  * invoices: kas pateikė (ext_email, ext_name), eilutės (lines), šaltinis (source)
-- Reikia: invoices.sql. Funkcija: supabase functions deploy freelance-portal --no-verify-jwt
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.invoices add column if not exists ext_email text;
alter table public.invoices add column if not exists ext_name  text;
alter table public.invoices add column if not exists lines     jsonb;
alter table public.invoices add column if not exists source    text;

create table if not exists public.fl_portal_pins (
  id          uuid primary key default gen_random_uuid(),
  email       text not null,
  pin_hash    text not null,
  expires_at  timestamptz not null,
  attempts    integer not null default 0,
  used_at     timestamptz,
  created_at  timestamptz not null default now()
);
create index if not exists fl_portal_pins_email on public.fl_portal_pins (email, created_at desc);

create table if not exists public.fl_portal_sessions (
  token_hash  text primary key,
  email       text not null,
  name        text,
  contact_id  text,
  expires_at  timestamptz not null,
  created_at  timestamptz not null default now()
);

-- tik serverio funkcija (service role): jokių taisyklių programai ar svečiams
alter table public.fl_portal_pins enable row level security;
alter table public.fl_portal_sessions enable row level security;
revoke all on public.fl_portal_pins, public.fl_portal_sessions from anon, authenticated;

notify pgrst, 'reload schema';
