-- ============================================================
-- Supabase „Disk IO Budget“ (2): suplanuotos pašto užduotys naktį ilsisi
--  * greitas pašto tikrinimas („mail-sync-fast“, kas 30 s) – tik 7:00–22:00 Lietuvos laiku;
--  * pilnas („mail-sync“, kas 2 min.) – naktį tik kas 10 min. (automatinis atsakymas, sąskaitų dėžutė,
--    įmonės pašto kopijavimas į Gmail vyksta su juo);
--  * suplanuotų užduočių žurnalas valomas kas valandą (jei disk_io.sql dar nepaleistas).
-- Kartu su „mail“ funkcija v37 (diegiama automatiškai): greitas tikrinimas nebeperrašo „patikrinta“ žymės, kai
-- niekas nepasikeitė, o sąskaitų dėžutė ir įmonės pašto kopijavimas – tik su pilnu tikrinimu.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
do $$
declare secret text;
begin
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret from cron.job where jobname = 'mail-sync';
  if secret is null then
    select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret from cron.job where jobname = 'mail-sync-fast';
  end if;
  if secret is null then raise exception 'Nerastas CRON_SECRET (nėra mail-sync užduoties) – pirmiausia paleisk mail_viskas.sql.'; end if;

  perform cron.unschedule(jobid) from cron.job where jobname = 'mail-sync-fast';
  perform cron.schedule('mail-sync-fast', '30 seconds', format($job$
    select net.http_post(
      url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/mail',
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', %L),
      body    := '{"action":"sync_all","quick":true}'::jsonb,
      timeout_milliseconds := 30000
    ) where extract(hour from now() at time zone 'Europe/Vilnius') between 7 and 21;
  $job$, secret));

  perform cron.unschedule(jobid) from cron.job where jobname = 'mail-sync';
  perform cron.schedule('mail-sync', '*/2 * * * *', format($job$
    select net.http_post(
      url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/mail',
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', %L),
      body    := '{"action":"sync_all"}'::jsonb,
      timeout_milliseconds := 110000
    ) where extract(hour from now() at time zone 'Europe/Vilnius') between 7 and 21
         or extract(minute from now())::int %% 10 = 0;
  $job$, secret));

  perform cron.unschedule(jobid) from cron.job where jobname = 'cron-log-cleanup';
  perform cron.schedule('cron-log-cleanup', '17 * * * *', $c$delete from cron.job_run_details where end_time < now() - interval '1 day'$c$);
end $$;
delete from cron.job_run_details where end_time < now() - interval '1 day';

select jobname, schedule, active from cron.job order by jobname;
