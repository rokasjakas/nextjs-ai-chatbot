-- Dingę daiktai – diagnostika: slack-sync {action:"diag"} praneša apie paėmimo „Šviesiai Garsiai“ daikto MDG trūkumą
-- (kaip mygtukas „Pranešti apie trūkumą“); su 'picker' – tik „Kam kasdien priminti“ laukas po jau išsiųsta žinute; Slack atsakymas – lost_diag_read.sql. Nieko netrina.
select net.http_post(
  url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/slack-sync',
  headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret',
               (select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') from cron.job where jobname = 'slack-sweep')),
  body    := jsonb_build_object('action', 'diag', 'picker', true, 'rental_id', 'rt_ehs6z4uqpgg',
               'item_id', (select i->>'id' from public.rentals r, jsonb_array_elements(r.data->'list') i where r.id = 'rt_ehs6z4uqpgg' and i->>'name' = 'MDG' limit 1)),
  timeout_milliseconds := 60000
) as request_id;
