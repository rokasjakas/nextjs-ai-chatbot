-- Slack diagnostikos atsakymas (tik skaito): slack-sync atsakymai ir renginio kanalas
select 'atsakymas' as k, created::text || ' · ' || status_code::text || ' · ' || left(coalesce(content::text, error_msg, ''), 2500) as v
  from net._http_response where content::text like '%"token"%' or content::text like '%Slack%' or content::text like '%slack%' or error_msg is not null order by id desc limit 4;
select 'kanalas' as k, event_id || ' · #' || name || ' · ' || url || ' · pakviesta: ' || coalesce(array_length(invited, 1), 0)::text || ' · ' || coalesce(last_error, '') as v from public.slack_channels;
