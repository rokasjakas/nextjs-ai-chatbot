-- Paskutiniai serverio funkcijų atsakymai (tik skaito): kas minutę vykstantys priminimai ir patikros
select id::text as k, created::text || ' · ' || coalesce(status_code::text, '-') || ' · ' || coalesce(error_msg, '') || ' · ' || left(coalesce(content::text, ''), 600) as v
  from net._http_response where created > now() - interval '15 minutes' order by id desc limit 12;
select 'cron' as k, jobname || ' · ' || schedule || ' · ' || active::text as v from cron.job where jobname in ('meeting-reminders', 'slack-sweep');
select 'run' as k, coalesce(j.jobname, '') || ' · ' || d.status || ' · ' || d.start_time::text || ' · ' || left(coalesce(d.return_message, ''), 200) as v
  from cron.job_run_details d left join cron.job j on j.jobid = d.jobid where j.jobname = 'meeting-reminders' order by d.start_time desc limit 3;
