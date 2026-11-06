-- Tik skaito: bandomųjų priminimų laiškų atsakymas (push-notify)
select 'atsakymas' as k, created::text || ' · ' || status_code::text || ' · ' || left(coalesce(content::text, error_msg, ''), 600) as v
  from net._http_response where created > now() - interval '15 minutes' and (content::text like '%freelancer%' or content::text like '%labor%' or content::text like '%adresas%' or content::text like '%nėra atliktų%' or content::text like '%Unauthorized%')
 order by id desc limit 3;
