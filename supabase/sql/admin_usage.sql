-- ============================================================
-- Admin → „Limitai ir naudojimas“: kiek užima duomenų bazė ir failų saugykla
--  * admin_usage() – tik administratoriams (role = 'admin')
--  * duomenų bazės dydis, didžiausios lentelės, failai pagal saugyklas
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.admin_usage() returns jsonb
  language plpgsql stable security definer set search_path = public, storage as $$
declare r jsonb;
begin
  if not coalesce((select role = 'admin' from public.profiles where id = auth.uid()), false) then
    raise exception 'Tik administratoriams';
  end if;
  select jsonb_build_object(
    'db_bytes', pg_database_size(current_database()),
    'tables', coalesce((select jsonb_agg(t) from (
        select c.relname as name, pg_total_relation_size(c.oid) as bytes, c.reltuples::bigint as rows
          from pg_class c join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'public' and c.relkind = 'r'
         order by pg_total_relation_size(c.oid) desc limit 8) t), '[]'::jsonb),
    'buckets', coalesce((select jsonb_agg(b) from (
        select o.bucket_id as name, count(*) as files, coalesce(sum((o.metadata->>'size')::bigint), 0) as bytes
          from storage.objects o group by o.bucket_id order by 3 desc) b), '[]'::jsonb),
    'members', (select count(*) from public.profiles where role <> 'pending'),
    'at', now()
  ) into r;
  return r;
end $$;
revoke all on function public.admin_usage() from public, anon;
grant execute on function public.admin_usage() to authenticated;
