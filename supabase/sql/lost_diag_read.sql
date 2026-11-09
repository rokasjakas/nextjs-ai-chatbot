-- Dingę daiktai – diagnostikos atsakymas (tik skaito)
select 'atsakymas' as k, created::text || ' · ' || status_code::text || ' · ' || left(coalesce(content::text, error_msg, ''), 2500) as v
  from net._http_response where content::text like '%missing%' or content::text like '%token%' or error_msg is not null order by id desc limit 3;
