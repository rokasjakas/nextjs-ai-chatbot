-- Linkėjimų patikra (tik skaitymas, tik skaičiai): kiek eilučių įrašyta / pakeista / ištrinta nuo statistikos pradžios
select 'stat' as k, relname, n_tup_ins, n_tup_upd, n_tup_del, n_live_tup, n_dead_tup, last_autovacuum, last_autoanalyze
from pg_stat_user_tables where schemaname = 'public' and relname in ('wishes', 'wish_boards', 'wish_reactions', 'poll_assets') order by relname;
select 'reset' as k, stats_reset from pg_stat_database where datname = current_database();
select 'triggers' as k, event_object_table, trigger_name from information_schema.triggers where event_object_table in ('wishes', 'wish_boards');
select 'cron' as k, jobname, schedule, left(command, 160) from cron.job order by jobid;
