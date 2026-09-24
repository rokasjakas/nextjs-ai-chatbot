-- ============================================================
-- Žmonės: kontaktų archyvas ir bookingas (skambučių žurnalas)
--  * nauja skiltis 'people' — Žmonės (Admin → teisės)
--  * contacts — visi turimi kontaktai (grupės, el. paštas, telefonas, adresas)
--  * contact_calls — kas, kada ir kuriai dienai skambino ir kuo baigėsi
--    (sutiko / negali / plačiau / neatsiliepė); matosi visiems, kas turi
--    prieigą, realiu laiku — kad tam pačiam žmogui tą pačią dieną
--    niekas neskambintų antrą kartą.
-- Paleisti PO handovers.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people'));

insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','people',true,true), ('office','people',true,true), ('tech','people',false,false),
  ('freelance','people',false,false), ('runner','people',false,false)
on conflict (role, section) do nothing;

create table if not exists public.contacts (
  id         text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);
alter table public.contacts enable row level security;
drop policy if exists "view contacts" on public.contacts;
create policy "view contacts" on public.contacts
  for select to authenticated using (public.can_view('people'));
drop policy if exists "edit contacts" on public.contacts;
create policy "edit contacts" on public.contacts
  for all to authenticated using (public.can_edit('people')) with check (public.can_edit('people'));

create table if not exists public.contact_calls (
  id          uuid primary key default gen_random_uuid(),
  contact_id  text not null references public.contacts(id) on delete cascade,
  for_date    date,                       -- kuriai dienai ieškomi žmonės
  event_id    text,                       -- renginys (nebūtina)
  outcome     text not null default 'calling'
              check (outcome in ('calling','sutiko','negali','placiau','neatsiliepe')),
  note        text,
  called_at   timestamptz not null default now(),
  called_by   uuid not null default auth.uid() references auth.users(id) on delete cascade,
  caller_name text
);
create index if not exists contact_calls_contact_idx on public.contact_calls (contact_id, called_at desc);
create index if not exists contact_calls_date_idx on public.contact_calls (for_date);
alter table public.contact_calls enable row level security;
drop policy if exists "view calls log" on public.contact_calls;
create policy "view calls log" on public.contact_calls
  for select to authenticated using (public.can_view('people'));
drop policy if exists "log own calls" on public.contact_calls;
create policy "log own calls" on public.contact_calls
  for insert to authenticated with check (public.can_edit('people') and called_by = auth.uid());
drop policy if exists "update own calls" on public.contact_calls;
create policy "update own calls" on public.contact_calls
  for update to authenticated using (called_by = auth.uid() and public.can_edit('people'))
  with check (called_by = auth.uid());
drop policy if exists "delete own calls" on public.contact_calls;
create policy "delete own calls" on public.contact_calls
  for delete to authenticated using (called_by = auth.uid() or public.is_admin());
-- who called and when is fixed once written; only the outcome and the note change
revoke update on public.contact_calls from authenticated;
grant update (outcome, note) on public.contact_calls to authenticated;

-- skambučiai matosi kitiems iškart
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'contact_calls') then
      execute 'alter publication supabase_realtime add table public.contact_calls';
    end if;
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'contacts') then
      execute 'alter publication supabase_realtime add table public.contacts';
    end if;
  end if;
end $$;
