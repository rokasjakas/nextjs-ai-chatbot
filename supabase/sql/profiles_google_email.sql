-- Profilis: atskiras Google paskyros el. paštas (Google Drive renginių aplankams), kai darbo paštas nėra Google paskyra
alter table public.profiles add column if not exists google_email text;
notify pgrst, 'reload schema';
select 'google_email' as k, count(*)::text as v from information_schema.columns where table_schema = 'public' and table_name = 'profiles' and column_name = 'google_email';
