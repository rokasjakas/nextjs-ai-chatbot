-- Tik skaito: renginių Slack kanalai – nuoroda, pakviesti, klaidos; paskutiniai slack-sync atsakymai
select 'kanalas' as k, event_id || ' · #' || name || ' · ' || url || ' · id ' || channel_id || ' · pakviesta: ' || coalesce(array_length(invited, 1), 0)::text || ' · ' || array_to_string(invited, ',') || ' · klaida: ' || coalesce(last_error, '') as v from public.slack_channels;
select 'atsakymas' as k, created::text || ' · ' || status_code::text || ' · ' || left(coalesce(content::text, error_msg, ''), 1500) as v
  from net._http_response where content::text ilike '%slack%' or content::text like '%"ok"%' order by id desc limit 3;
