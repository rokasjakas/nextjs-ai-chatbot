-- ============================================================
-- Ofisas → Share dokumentai: bendrų dokumentų nuorodos (Google Sheets, Docs, Drive ir kt.)
-- Eilutė: pavadinimas, kas tai (aprašymas), grupė, nuoroda. Mato ir tvarko Office ir aukštesni lygiai.
-- Saugu paleisti pakartotinai.
-- ============================================================
create or replace function public.office_can() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.is_approved() and public.my_role() in ('admin', 'pm', 'office'), false)
$$;
revoke all on function public.office_can() from public, anon;
grant execute on function public.office_can() to authenticated;

create table if not exists public.shared_docs (
  id               uuid primary key default gen_random_uuid(),
  title            text not null check (char_length(title) between 1 and 200),
  note             text not null default '',
  grp              text not null default '',
  url              text not null check (url ~* '^https?://'),
  sort             integer,
  created_by       uuid not null default auth.uid() references auth.users(id) on delete cascade,
  created_by_name  text,
  created_at       timestamptz not null default now(),
  updated_by_name  text,
  updated_at       timestamptz not null default now()
);
alter table public.shared_docs enable row level security;
drop policy if exists "shared docs office" on public.shared_docs;
create policy "shared docs office" on public.shared_docs for all to authenticated
  using (public.office_can()) with check (public.office_can());
revoke all on public.shared_docs from anon;
grant select, insert, update, delete on public.shared_docs to authenticated;

notify pgrst, 'reload schema';
select 'shared_docs ok' as result, (select count(*) from public.shared_docs) as docs;
