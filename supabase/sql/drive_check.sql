-- Tik skaito: Google Drive būsena (ar prijungta, ar įjungta, kiek aplankų) – be raktų
select 'prijungta' as k, coalesce((select coalesce(email,'?') || ' · aplankas ' || coalesce(root_id,'nėra') || ' · ' || coalesce(connected_by,'') || ' ' || connected_at::text || ' · raktas ' || case when refresh_token is null then 'NĖRA' else 'yra' end from public.gdrive_auth where id = 1), 'NE') as v
union all select 'įjungta', coalesce((select value::text from public.app_config where key = 'gdrive'), 'NE')
union all select 'aplankų', count(*)::text from public.event_drive
union all select 'įkėlimų iš Slack', count(*)::text from public.drive_uploads;
