-- Slack diagnostikos atsakymas (tik skaito): paskutiniai serverio užklausų atsakymai ir renginio kanalas
select 'atsakymas' as k, status_code::text || ' · ' || left(coalesce(content::text, error_msg, ''), 1500) as v from net._http_response order by id desc limit 3;
select 'kanalas' as k, event_id || ' · #' || name || ' · ' || url || ' · pakviesta: ' || array_length(invited, 1)::text || ' · ' || coalesce(last_error, '') as v from public.slack_channels;
