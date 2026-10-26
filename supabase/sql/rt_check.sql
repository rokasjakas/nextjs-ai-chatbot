-- Realtime ir nario nustatymų dydžio patikrinimas (tik skaito, nieko nekeičia; turinys ir vardai nerodomi).
-- Paleidžiamas per „SQL paleidimas“ (supabase/sql-run.txt = rt_check.sql).
select 'pub' as k, string_agg(tablename, ', ' order by tablename) as v from pg_publication_tables where pubname = 'supabase_realtime'
union all
select 'replid', * from (select c.relname || ' · ' || case c.relreplident when 'f' then 'FULL' when 'd' then 'default' else c.relreplident::text end
  from pg_class c join pg_namespace n on n.oid = c.relnamespace join pg_publication_tables p on p.schemaname = n.nspname and p.tablename = c.relname
  where p.pubname = 'supabase_realtime' and c.relreplident = 'f') r
union all
select 'subs', * from (select (s.entity::regclass)::text || ' · ' || count(*) || ' prenumeratų' from realtime.subscription s group by s.entity order by count(*) desc) s
union all
select 'prefs', 'nariai ' || count(*) || ' · vid. ' || pg_size_pretty(avg(pg_column_size(notify_prefs))::bigint) || ' · didž. ' || pg_size_pretty(max(pg_column_size(notify_prefs))::bigint)
  || ' · visi ' || pg_size_pretty(sum(pg_column_size(notify_prefs))::bigint) from public.profiles
union all
-- kurie raktai užima daugiausia (visų narių suma) – tik raktų pavadinimai ir dydžiai
select 'key', * from (select e.key || ' · ' || pg_size_pretty(sum(length(e.value::text))::bigint) || ' · narių ' || count(*)
  || ' · didž. ' || pg_size_pretty(max(length(e.value::text))::bigint)
  from public.profiles p, jsonb_each(case when jsonb_typeof(p.notify_prefs) = 'object' then p.notify_prefs else '{}'::jsonb end) e
  group by e.key order by sum(length(e.value::text)) desc limit 15) k;
