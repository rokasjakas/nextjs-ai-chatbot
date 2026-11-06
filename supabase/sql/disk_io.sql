-- ============================================================
-- Supabase „Disk IO Budget“: mažiau rašymo į duomenų bazę
--  1. pg_cron žurnalas (cron.job_run_details) – kiekvienas suplanuotos užduoties paleidimas įrašomas ir
--     niekada nevalomas (vien paštas – ~7 000 eilučių per dieną). Išvalomas dabar ir toliau kas valandą
--     (paliekama paskutinė para).
--  2. Pašto tikrinimas: greitas („mail-sync-fast“) – kas 30 s vietoj 15 s, pilnas („mail-sync“) – kas 2 min.
--     vietoj kas minutę. Nauji laiškai ir sąskaitos iš saskaitos@ atsiranda per ~30–60 s.
--  3. Pabaigoje – lentelės, į kurias rašoma daugiausia (atsiųsk šio rezultato nuotrauką – pagal ją
--     sumažinsime toliau).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- Grąžinti seną greitį: select cron.alter_job(jobid, schedule := '15 seconds') from cron.job where jobname = 'mail-sync-fast';
-- ============================================================

-- 1. cron žurnalas
delete from cron.job_run_details where end_time < now() - interval '1 day';
select cron.unschedule(jobid) from cron.job where jobname = 'cron-log-cleanup';
select cron.schedule('cron-log-cleanup', '17 * * * *', $$delete from cron.job_run_details where end_time < now() - interval '1 day'$$);

-- 2. pašto tikrinimas rečiau
select cron.alter_job(jobid, schedule := '30 seconds') from cron.job where jobname = 'mail-sync-fast';
select cron.alter_job(jobid, schedule := '*/2 * * * *') from cron.job where jobname = 'mail-sync';

-- kas dabar suplanuota
select jobname, schedule, active from cron.job order by jobname;

-- 3. daugiausia rašomos lentelės (nuo paskutinio statistikos nunulinimo)
select schemaname || '.' || relname as lentele,
       n_tup_ins as iterpta, n_tup_upd as atnaujinta, n_tup_del as istrinta, n_live_tup as eiluciu,
       pg_size_pretty(pg_total_relation_size(relid)) as dydis
from pg_stat_all_tables
where schemaname in ('public', 'cron', 'net', 'realtime', 'storage', 'auth')
order by (n_tup_ins + n_tup_upd + n_tup_del) desc
limit 15;
