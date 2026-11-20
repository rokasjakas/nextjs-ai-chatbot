-- Priminimų inventorius (tik skaitymas): pg_cron darbai ir su priminimais susijusios lentelės
select 'cron' as k, jobname, schedule, active, left(regexp_replace(command, '(x-cron-secret''\s*,\s*'')[^'']+', '\1***', 'g'), 220) as cmd from cron.job order by jobname;
select 'tbl' as k, table_name from information_schema.tables where table_schema='public' and (table_name ilike '%remind%' or table_name ilike '%notif%' or table_name ilike '%report_%' or table_name ilike '%labor%' or table_name ilike '%work_plan%') order by 1,2;
select 'state' as k, key, left(value::text, 160) from public.app_state where key ilike any (array['%remind%','%notif%','%labor%','%report%','%mail%','%cron%']) order by key;
