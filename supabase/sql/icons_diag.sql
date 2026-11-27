-- Slack ikonos – patikra: slack-sync {action:"diag"} (be renginio) parodo, kurias ms-… ikonas botas mato; atsakymas – lost_diag_read.sql.
select net.http_post(
  url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/slack-sync',
  headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret',
               (select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') from cron.job where jobname = 'slack-sweep')),
  body    := '{"action":"diag"}'::jsonb,
  timeout_milliseconds := 30000
) as request_id;
