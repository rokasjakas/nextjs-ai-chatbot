-- ============================================================
-- „Inventorizacija“ (Sandėlis)
--  * stk_items    — inventorizacijos registras: skyrius (Excel lapas), grupė,
--                   pavadinimas, kiekis, komentaras, kiti Excel stulpeliai (extra),
--                   ryšys su sandėlio daiktu (item_id), archyvavimas su priežastimi
--  * stk_sessions — inventorizacijos (Excel stulpeliai ir naujos programoje):
--                   data ir suskaičiuoti kiekiai (counts: {stk_items.id: kiekis})
--  * stk_log      — kiekių keitimai, archyvavimai ir kt. su priežastimis
--                   (tik pridedama: redaguoti ar trinti negalima)
--  * mato tie, kas mato „Sandėlį“, keičia — kas jį redaguoja
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.stk_items (
  id              text primary key,
  sheet           text not null default '',
  section         text not null default '',
  name            text not null default '',
  qty             numeric,
  qty_text        text not null default '',
  comment         text not null default '',
  extra           jsonb not null default '{}'::jsonb,
  color           text not null default '',
  item_id         text,
  archived        boolean not null default false,
  archived_reason text,
  archived_at     timestamptz,
  sort            double precision not null default 0,
  sheet_sort      double precision,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  updated_by      text
);
create index if not exists stk_items_sheet on public.stk_items (sheet, sort);

create table if not exists public.stk_sessions (
  id         text primary key,
  sheet      text not null default '',
  date       date,
  label      text not null default '',
  status     text not null default 'done',
  counts     jsonb not null default '{}'::jsonb,
  notes      jsonb not null default '{}'::jsonb,
  source     text not null default 'app',
  sort       double precision not null default 0,
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  updated_by text
);
create index if not exists stk_sessions_sheet on public.stk_sessions (sheet, date);

create table if not exists public.stk_log (
  id       bigint generated always as identity primary key,
  at       timestamptz not null default now(),
  by_id    uuid default auth.uid(),
  by_name  text,
  stk_id   text,
  sheet    text,
  name     text,
  action   text not null,
  from_v   text,
  to_v     text,
  reason   text
);
create index if not exists stk_log_item on public.stk_log (stk_id, at desc);
create index if not exists stk_log_sheet on public.stk_log (sheet, at desc);

-- kiekio keitimas ir archyvavimas be priežasties neišsaugomas ir serveryje
alter table public.stk_log drop constraint if exists stk_log_reason;
alter table public.stk_log add constraint stk_log_reason
  check (action not in ('qty','warehouse_qty','archive','restore') or length(btrim(coalesce(reason,''))) >= 3);
alter table public.stk_items drop constraint if exists stk_items_archive_reason;
alter table public.stk_items add constraint stk_items_archive_reason
  check (not archived or length(btrim(coalesce(archived_reason,''))) >= 3);

alter table public.stk_items enable row level security;
drop policy if exists "view stk_items" on public.stk_items;
create policy "view stk_items" on public.stk_items
  for select to authenticated using (public.can_view('inventory'));
drop policy if exists "edit stk_items" on public.stk_items;
create policy "edit stk_items" on public.stk_items
  for all to authenticated using (public.can_edit('inventory')) with check (public.can_edit('inventory'));
grant select, insert, update, delete on public.stk_items to authenticated;

alter table public.stk_sessions enable row level security;
drop policy if exists "view stk_sessions" on public.stk_sessions;
create policy "view stk_sessions" on public.stk_sessions
  for select to authenticated using (public.can_view('inventory'));
drop policy if exists "edit stk_sessions" on public.stk_sessions;
create policy "edit stk_sessions" on public.stk_sessions
  for all to authenticated using (public.can_edit('inventory')) with check (public.can_edit('inventory'));
grant select, insert, update, delete on public.stk_sessions to authenticated;

alter table public.stk_log enable row level security;
drop policy if exists "view stk_log" on public.stk_log;
create policy "view stk_log" on public.stk_log
  for select to authenticated using (public.can_view('inventory'));
drop policy if exists "add stk_log" on public.stk_log;
create policy "add stk_log" on public.stk_log
  for insert to authenticated with check (public.can_edit('inventory'));
grant select, insert on public.stk_log to authenticated;

-- v105: atskiri vienetai („… Nr.1“, „Nr.2“ …) po modelio eilute, kaip „Vaizdas NEW“
alter table public.stk_items add column if not exists parent_id text;
create index if not exists stk_items_parent on public.stk_items (parent_id);
