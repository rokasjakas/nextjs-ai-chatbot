-- Patikrinimas (nieko nekeičia): ar GitHub prisijungia prie duomenų bazės, kokios suplanuotos užduotys,
-- kur daugiausia rašoma. Paleidžiamas per „SQL paleidimas“ (supabase/sql-run.txt = db_check.sql).
select 'cron' as k, jobname || ' · ' || schedule || ' · ' || case when active then 'aktyvi' else 'išjungta' end as v from cron.job
union all
select 'top', * from (
  select schemaname || '.' || relname || ' · įt ' || n_tup_ins || ' · atn ' || n_tup_upd || ' · ištr ' || n_tup_del || ' · ' || pg_size_pretty(pg_total_relation_size(relid))
  from pg_stat_all_tables where schemaname in ('public','cron','net','realtime','storage','auth')
  order by (n_tup_ins + n_tup_upd + n_tup_del) desc limit 8) t
union all
select 'db', pg_size_pretty(pg_database_size(current_database()));
