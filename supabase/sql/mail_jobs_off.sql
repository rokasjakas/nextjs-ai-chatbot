-- ============================================================
-- „El. paštas“ išjungimas – tik suplanuotos užduotys (nieko netrina):
--  * išjungiamos pašto dėžučių užduotys mail-sync, mail-sync-fast, mail-auto-reply;
--  * sąskaitų dėžutė saskaitos@ toliau tikrinama užduotimi „invoice-inbox“ kas 2 min. (naktį 22–7 – kas 10 min.).
-- Laiškų kopijų išvalymas ir kita – supabase/sql/mail_off.sql (paleidžiama ranka).
-- ============================================================
do $$
declare secret text;
begin
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
    from cron.job where jobname in ('mail-sync', 'mail-sync-fast', 'invoice-inbox', 'vehicle-reminders-daily') and command like '%x-cron-secret%' limit 1;
  if secret is null then raise exception 'Nerastas CRON_SECRET suplanuotose užduotyse.'; end if;

  perform cron.unschedule(jobid) from cron.job where jobname in ('mail-sync', 'mail-sync-fast', 'mail-auto-reply', 'invoice-inbox');
  perform cron.schedule('invoice-inbox', '*/2 * * * *', format($job$
    select net.http_post(
      url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/mail',
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', %L),
      body    := '{"action":"invoice_inbox"}'::jsonb,
      timeout_milliseconds := 110000
    ) where extract(hour from now() at time zone 'Europe/Vilnius') between 7 and 21
         or extract(minute from now())::int %% 10 = 0;
  $job$, secret));

end $$;

select jobname, schedule, active from cron.job order by jobname;
