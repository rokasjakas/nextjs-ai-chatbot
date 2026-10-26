-- Disko apkrovos (Disk IO) patikrinimas (tik skaito, nieko nekeičia): kas skaito ir rašo diską daugiausia.
-- Paleidžiamas per „SQL paleidimas“ (supabase/sql-run.txt = io_check.sql).
select 'nuo' as k, 'statistika nuo ' || coalesce((select stats_reset::text from pg_stat_database where datname = current_database()), '?')
  || ' · serveris paleistas ' || pg_postmaster_start_time()::text as v
union all
select 'db', pg_size_pretty(pg_database_size(current_database())) || ' · atmintis ' || current_setting('shared_buffers')
  || ' · iš atminties ' || round(100.0 * blks_hit / nullif(blks_hit + blks_read, 0), 2) || '% · disko skaitymų ' || blks_read
  || ' · laikini failai ' || pg_size_pretty(temp_bytes)
  from pg_stat_database where datname = current_database()
union all
-- realtime / replikacijos lizdai: sulaikytas WAL gula ant disko
select 'slot', * from (select slot_name || ' · ' || coalesce(plugin, '') || ' · aktyvus ' || active || ' · sulaiko WAL '
  || pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) from pg_replication_slots) s
union all
select 'rt', count(*)::text || ' realtime prenumeratų (postgres_changes)' from realtime.subscription
union all
-- lentelės, kurias daugiausia tenka skaityti iš disko (ne iš atminties)
select 'read', * from (select schemaname || '.' || relname || ' · disk ' || (coalesce(heap_blks_read, 0) + coalesce(idx_blks_read, 0) + coalesce(toast_blks_read, 0))
  || ' · atm ' || (coalesce(heap_blks_hit, 0) + coalesce(idx_blks_hit, 0)) || ' · ' || pg_size_pretty(pg_total_relation_size(relid))
  from pg_statio_all_tables where schemaname not in ('pg_catalog', 'information_schema', 'pg_toast')
  order by coalesce(heap_blks_read, 0) + coalesce(idx_blks_read, 0) + coalesce(toast_blks_read, 0) desc limit 10) r
union all
-- lentelės, į kurias daugiausia rašoma
select 'write', * from (select schemaname || '.' || relname || ' · įt ' || n_tup_ins || ' · atn ' || n_tup_upd || ' · ištr ' || n_tup_del
  || ' · negyvų ' || n_dead_tup || ' · seq ' || seq_scan || ' · ' || pg_size_pretty(pg_total_relation_size(relid))
  from pg_stat_all_tables where schemaname not in ('pg_catalog', 'information_schema', 'pg_toast')
  order by n_tup_ins + n_tup_upd + n_tup_del desc limit 10) w
union all
-- užklausos, kurios daugiausia skaito / rašo diską
select 'q', * from (select (shared_blks_read + shared_blks_written + temp_blks_read + temp_blks_written) || ' blokų · ' || calls || '× · WAL '
  || pg_size_pretty(wal_bytes) || ' · ' || left(regexp_replace(query, '\s+', ' ', 'g'), 150)
  from pg_stat_statements where query not ilike '%pg_stat%'
  order by shared_blks_read + shared_blks_written + temp_blks_read + temp_blks_written desc limit 12) q
union all
select 'cron', * from (select j.jobname || ' · ' || j.schedule || ' · ' || case when j.active then 'aktyvi' else 'išjungta' end
  || ' · per 24 val. ' || count(d.runid) || '× · vid. ' || coalesce(round(avg(extract(epoch from d.end_time - d.start_time))::numeric * 1000)::text, '-') || ' ms'
  from cron.job j left join cron.job_run_details d on d.jobid = j.jobid and d.start_time > now() - interval '24 hours'
  group by j.jobid, j.jobname, j.schedule, j.active order by count(d.runid) desc) c
union all
select 'size', * from (select n.nspname || '.' || c.relname || ' · ' || pg_size_pretty(pg_total_relation_size(c.oid))
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where c.relkind = 'r' and n.nspname not in ('pg_catalog', 'information_schema', 'pg_toast')
  order by pg_total_relation_size(c.oid) desc limit 8) z;
