-- Inventorizacija ↔ Įranga (tik skaito, nieko nekeičia): kurios eilutės susietos su „Pulse Bar S“ (2596),
-- jo kiekis Įrangoje, ir kokius Įrangos kiekius bei susiejimus programa pakeitė per paskutines 2 dienas.
select 'eilute' as k, sheet || ' / ' || coalesce(section,'') || ' · ' || name || ' · qty=' || coalesce(qty::text,'null') || ' · arch=' || archived || ' · parent=' || coalesce(parent_id,'-') as v
  from public.stk_items where item_id = '2596' or name ilike '%pulse bar%'
union all
select 'iranga 2596', coalesce((data->'2596')::text, 'nėra override') from public.app_state where key = 'itemOverrides'
union all
select 'log ' || action, count(*)::text from public.stk_log where at > now() - interval '2 days' and action in ('link','warehouse_qty') group by action
union all
select 'log wq', name || ': ' || from_v || '→' || to_v || ' (' || coalesce(reason,'') || ')'
  from public.stk_log where at > now() - interval '2 days' and action = 'warehouse_qty' and name ilike '%pulse%'
union all
select 'eiluciu su keliais', count(*)::text from (select item_id from public.stk_items where item_id is not null and not archived and parent_id is null group by item_id having count(*) > 1) x;
