-- Dingę daiktai (tik skaito): paėmimų daiktai su grąžinimo vienetais / pranešimu ir paskutiniai slack-sync atsakymai
select 'daiktas' as k, r.id || ' · ' || coalesce(r.data->>'place', '') || ' · ' || coalesce(i->>'name', '') || ' · paimta ' || coalesce(i->>'qty', '') ||
       ' · grąžinama ' || coalesce(i->>'backQty', '-') || ' · back ' || coalesce(i->>'back', '-') || ' · lost ' || coalesce(i->>'lost', '-') || ' · ' || r.updated_at::text || ' ' || coalesce(r.updated_by, '') as v
  from public.rentals r, jsonb_array_elements(coalesce(r.data->'list', '[]'::jsonb)) i
 where i ? 'backQty' or i ? 'lost' or i ? 'back'
 order by r.updated_at desc limit 20;
select 'slack' as k, (select value::text from public.app_config where key = 'slack') as v;
select 'kanalai' as k, count(*)::text as v from public.slack_channels where archived_at is null;
