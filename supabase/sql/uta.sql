-- ============================================================
-- Transportas → „UTA kortelės“
--  * uta_cards   – kuro kortelės: numeris, kam priskirta (transportui
--                  arba asmeniui), galiojimas, pastabos
--  * uta_reports – įkeltos mėnesio ataskaitos (Excel / CSV iš UTA)
--  * uta_tx      – ataskaitų eilutės: kada, kur, kas pilta, kiek, už kiek.
--                  Tas pats pylimas iš dviejų ataskaitų įrašomas tik kartą (key).
-- Mato visi, kas mato „Transportą“; keisti ir įkelti – kas jį redaguoja.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.uta_cards (
  id            uuid primary key default gen_random_uuid(),
  card_no       text not null check (length(card_no) between 4 and 40),
  title         text not null default '',
  assign_kind   text not null default 'none' check (assign_kind in ('vehicle','person','none')),
  vehicle_id    text,
  vehicle_name  text,
  person_id     uuid,
  person_name   text,
  valid_until   date,
  note          text not null default '',
  active        boolean not null default true,
  created_by    uuid default auth.uid(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
-- the same card once (spaces and dashes aside)
create unique index if not exists uta_cards_no on public.uta_cards (regexp_replace(card_no, '[^0-9A-Za-z]', '', 'g'));

create table if not exists public.uta_reports (
  id                uuid primary key default gen_random_uuid(),
  month             date not null,
  file_name         text not null default '',
  rows              integer not null default 0,
  uploaded_by       uuid default auth.uid(),
  uploaded_by_name  text,
  created_at        timestamptz not null default now()
);

create table if not exists public.uta_tx (
  id            uuid primary key default gen_random_uuid(),
  report_id     uuid references public.uta_reports(id) on delete cascade,
  card_no       text not null default '',
  card_id       uuid references public.uta_cards(id) on delete set null,
  tx_at         timestamptz not null,
  tx_date       date not null,
  plate         text,
  station       text,
  country       text,
  product       text,
  quantity      numeric(12,3),
  unit          text,
  amount_net    numeric(12,2),
  amount_gross  numeric(12,2),
  currency      text,
  mileage       integer,
  driver        text,
  key           text not null unique
);
create index if not exists uta_tx_date on public.uta_tx (tx_date);
create index if not exists uta_tx_card on public.uta_tx (card_id, tx_date);

alter table public.uta_cards enable row level security;
alter table public.uta_reports enable row level security;
alter table public.uta_tx enable row level security;

drop policy if exists "uta cards view" on public.uta_cards;
create policy "uta cards view" on public.uta_cards for select to authenticated using (public.can_view('fleet'));
drop policy if exists "uta cards edit" on public.uta_cards;
create policy "uta cards edit" on public.uta_cards for all to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));

drop policy if exists "uta reports view" on public.uta_reports;
create policy "uta reports view" on public.uta_reports for select to authenticated using (public.can_view('fleet'));
drop policy if exists "uta reports edit" on public.uta_reports;
create policy "uta reports edit" on public.uta_reports for all to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));

drop policy if exists "uta tx view" on public.uta_tx;
create policy "uta tx view" on public.uta_tx for select to authenticated using (public.can_view('fleet'));
drop policy if exists "uta tx edit" on public.uta_tx;
create policy "uta tx edit" on public.uta_tx for all to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));

revoke all on public.uta_cards, public.uta_reports, public.uta_tx from anon;
grant select, insert, update, delete on public.uta_cards, public.uta_reports, public.uta_tx to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';
