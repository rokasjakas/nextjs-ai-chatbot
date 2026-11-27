-- Vietos atlaisvinimas: cron.job_run_details po žurnalo išvalymo vis dar užima ~160 MB disko (ištrintos eilutės).
-- VACUUM FULL perrašo lentelę tik su likusiomis eilutėmis (nieko netrina). Paleidžiama per „SQL paleidimas“.
vacuum full cron.job_run_details;
select 'cron.job_run_details' as lentele, pg_size_pretty(pg_total_relation_size('cron.job_run_details')) as dydis
union all select 'visa DB', pg_size_pretty(pg_database_size(current_database()));
