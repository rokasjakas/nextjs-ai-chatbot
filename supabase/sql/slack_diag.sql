-- Slack diagnostika: paleidžia slack-sync {action:"diag"} renginiui „TESTAS“ (ev_mdeei04ovgk) – sukuria / atnaujina jo kanalą,
-- kaip ir išsaugojus renginį; atsakymas – kitame paleidime (slack_diag_read.sql). Nieko netrina.
select net.http_post(
  url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/slack-sync',
  headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret',
               (select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') from cron.job where jobname = 'slack-sweep')),
  body    := '{"action":"diag","event_id":"ev_mdeei04ovgk"}'::jsonb,
  timeout_milliseconds := 60000
) as request_id;
