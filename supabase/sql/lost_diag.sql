-- Dingę daiktai – diagnostika: slack-sync {action:"diag"} praneša apie paėmimo „Solist Pro“ daikto „2m Juodos kojines“ trūkumą
-- (kaip mygtukas „Pranešti apie trūkumą“); Slack atsakymas – lost_diag_read.sql. Nieko netrina.
select net.http_post(
  url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/slack-sync',
  headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret',
               (select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') from cron.job where jobname = 'slack-sweep')),
  body    := jsonb_build_object('action', 'diag', 'rental_id', 'rt_1ngpvmobwtk',
               'item_id', (select i->>'id' from public.rentals r, jsonb_array_elements(r.data->'list') i where r.id = 'rt_1ngpvmobwtk' and i->>'name' = '2m Juodos kojines' limit 1)),
  timeout_milliseconds := 60000
) as request_id;
