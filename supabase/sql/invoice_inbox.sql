-- ============================================================
-- Sąskaitos iš el. pašto: saskaitos@eventsolutions.lt
--  * kiekvienas naujas laiškas į sąskaitų dėžutę tampa sąskaita „Sąskaitose“
--    (priedai – sąskaitos failai; suma randama PDF'e; tiekėjas – siuntėjas)
--  * rūšis parenkama pagal raktažodžius (Admin+ nustato: „📥 Sąskaitų dėžutė“);
--    nepritaikius jokios taisyklės – numatytoji rūšis (pvz. „Kitos“)
--  * invoice_inbox – dėžutės prisijungimas (slaptažodis užšifruotas), taisyklės, būsena;
--    pasiekiama tik per „mail“ funkciją
--  * invoices.mail_id – laiško Message-ID (tas pats laiškas neįkeliamas du kartus)
-- Reikia: invoices.sql. Funkcijos: mail (v28), push-notify.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- nauja rūšis „Kitos“ (nesurūšiuotos)
alter table public.invoices drop constraint if exists invoices_kind_check;
alter table public.invoices add constraint invoices_kind_check check (kind in ('freelance','service','rent','purchase','other'));

alter table public.invoices add column if not exists source    text;
alter table public.invoices add column if not exists ext_email text;
alter table public.invoices add column if not exists ext_name  text;
alter table public.invoices add column if not exists mail_id   text;
create unique index if not exists invoices_mail_id on public.invoices (mail_id) where mail_id is not null;

create table if not exists public.invoice_inbox (
  id            integer primary key default 1 check (id = 1),
  email         text,
  host          text,
  secret        text,
  active        boolean not null default false,
  rules         jsonb not null default '[]'::jsonb,   -- [{kw:"lemona, ignitis", where:"any|from|subject|text|file", kind, supplier}]
  default_kind  text not null default 'other',
  state         jsonb not null default '{}'::jsonb,
  updated_at    timestamptz not null default now()
);
alter table public.invoice_inbox enable row level security;
revoke all on public.invoice_inbox from anon, authenticated;

notify pgrst, 'reload schema';
