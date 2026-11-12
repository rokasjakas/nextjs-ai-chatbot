-- Kodėl Renginiuose nesimato „✉ Laiškas komandai“ (tik skaito, nieko nekeičia):
-- ar „El. paštas“ (mail) išjungtas lygiams / sistemoje ir kas jį mato pagal teises
select 'off.lv' as k, coalesce((select jsonb_pretty(value->'lv') from public.app_config where key = 'off'), 'nėra') as v
union all select 'off.tabs/ids', coalesce((select left((value - 'lv')::text, 1500) from public.app_config where key = 'off'), 'nėra')
union all select 'nav', coalesce((select left(value::text, 1500) from public.app_config where key = 'nav'), 'nėra')
union all select 'mail teisės', coalesce((select string_agg(role || '=' || case when can_edit then 'edit' when can_view then 'view' else '-' end, ', ' order by role) from public.role_permissions where section = 'mail'), 'nėra eilučių')
union all select 'events teisės', coalesce((select string_agg(role || '=' || case when can_edit then 'edit' when can_view then 'view' else '-' end, ', ' order by role) from public.role_permissions where section = 'events'), 'nėra eilučių');
