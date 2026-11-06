-- Bandomieji Darbų apskaitos priminimų laiškai (freelanceriui ir atsakingam) – tik į vieną adresą (savininko prašymu)
do $$
declare secret text;
begin
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret from cron.job where command like '%x-cron-secret%' order by jobid limit 1;
  if secret is null then raise exception 'Nerasta CRON_SECRET.'; end if;
  perform net.http_post(
    url := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/push-notify',
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', secret),
    body := jsonb_build_object('mode', 'labor-preview', 'to', 'rokasjakas0505@gmail.com'),
    timeout_milliseconds := 60000);
end $$;
select 'išsiųsta užklausa' as k, now()::text as v;
