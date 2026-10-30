-- ============================================================
-- Bolt / Wolt: failas išsaugomas ir tada, kai saugykla „bolt-files“ jo nepriima
-- (failas laikomas duomenų bazėje, iki 8 MB), ir diagnostika, kodėl nepavyksta įkelti.
-- Reikia: office_bolt.sql. Saugu paleisti pakartotinai.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- ============================================================

create table if not exists public.office_files (
  id          uuid primary key default gen_random_uuid(),
  kind        text not null default 'bolt' check (kind in ('bolt','wolt')),
  report_id   uuid,
  name        text not null default '',
  type        text,
  size        integer,
  data        text not null,                 -- base64
  created_by  uuid default auth.uid(),
  created_at  timestamptz not null default now()
);
alter table public.office_files enable row level security;
drop policy if exists "office files all" on public.office_files;
create policy "office files all" on public.office_files for all to authenticated
  using (public.office_admin()) with check (public.office_admin());
revoke all on public.office_files from anon;
grant select, insert, delete on public.office_files to authenticated;

-- what the server thinks of the one who uploads
create or replace function public.office_whoami() returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'role', public.my_role(),
    'office_admin', public.office_admin(),
    'bucket', exists (select 1 from storage.buckets where id = 'bolt-files'),
    'policies', coalesce((select jsonb_agg(policyname) from pg_policies where schemaname = 'storage' and tablename = 'objects' and policyname like 'bolt files%'), '[]'::jsonb),
    'tables', exists (select 1 from information_schema.tables where table_schema = 'public' and table_name = 'bolt_reports'))
$$;
grant execute on function public.office_whoami() to authenticated;

notify pgrst, 'reload schema';
