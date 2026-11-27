-- Slack patikrinimas (tik skaito, nieko nekeičia): ar įjungta, kokie kanalai, paskutiniai renginiai, kasdienė užduotis
select 'app_config slack' as k, coalesce((select value::text || ' · ' || coalesce(updated_name,'') || ' ' || updated_at::text from public.app_config where key = 'slack'), 'NĖRA (neįjungta)') as v
union all select 'slack_channels', count(*)::text from public.slack_channels
union all (select 'kanalas', event_id || ' · #' || name || ' · ' || coalesce(archived_at::text, 'atviras') || ' · ' || coalesce(last_error, '') from public.slack_channels order by created_at desc limit 5)
union all (select 'renginys', id || ' · ' || coalesce(data->>'kind','event') || ' · ' || coalesce(data->>'name', data->>'title', '') || ' · ' || coalesce(event_date::text, 'be datos') || ' · ' || updated_at::text from public.events order by updated_at desc limit 5)
union all select 'cron slack-sweep', coalesce((select schedule || case when active then ' aktyvi' else ' išjungta' end from cron.job where jobname = 'slack-sweep'), 'nėra');
