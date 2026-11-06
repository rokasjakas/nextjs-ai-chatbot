-- Sąskaitų dėžutė (saskaitos@) tikrinama kas valandą (buvo kas 2 min.) – mažiau Disk IO.
-- „Tikrinti dabar“ programoje veikia kaip anksčiau. Paleidžiama per „SQL paleidimas“. Saugu paleisti pakartotinai.
do $$
declare secret text;
begin
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
    from cron.job where jobname = 'invoice-inbox' and command like '%x-cron-secret%' limit 1;
  if secret is null then raise exception 'Nerasta užduotis invoice-inbox su CRON_SECRET.'; end if;
  perform cron.unschedule(jobid) from cron.job where jobname = 'invoice-inbox';
  perform cron.schedule('invoice-inbox', '7 * * * *', format($job$
    select net.http_post(
      url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/mail',
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', %L),
      body    := '{"action":"invoice_inbox"}'::jsonb,
      timeout_milliseconds := 110000
    );
  $job$, secret));
end $$;
select jobname || ' · ' || schedule || ' · ' || case when active then 'aktyvi' else 'išjungta' end as uzduotis from cron.job order by jobname;
