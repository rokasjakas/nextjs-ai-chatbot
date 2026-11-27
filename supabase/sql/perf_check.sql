-- Našumo patikrinimas (tik skaito): lėčiausios / dažniausios užklausos, lentelės be indeksų naudojimo, talpyklos efektyvumas.
select 'cache' as k, round(100.0 * sum(heap_blks_hit) / nullif(sum(heap_blks_hit) + sum(heap_blks_read), 0), 2)::text || '% iš atminties' as v from pg_statio_user_tables
union all
select 'conn', count(*)::text || ' prisijungimų (' || count(*) filter (where state = 'active') || ' aktyvūs)' from pg_stat_activity
union all
select 'seq', * from (select relname || ' · seq ' || seq_scan || ' · idx ' || coalesce(idx_scan, 0) || ' · eil. ' || n_live_tup
  from pg_stat_user_tables where seq_scan > 1000 and n_live_tup > 500 order by seq_tup_read desc limit 10) a
union all
select 'top', * from (select round(total_exec_time)::text || ' ms viso · ' || calls || '× · vid. ' || round(mean_exec_time::numeric, 1) || ' ms · ' || left(regexp_replace(query, '\s+', ' ', 'g'), 160)
  from pg_stat_statements where query not ilike '%pg_stat%' order by total_exec_time desc limit 15) b;
