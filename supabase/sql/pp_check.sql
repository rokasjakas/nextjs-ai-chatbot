-- Tik skaito: Žmonės – kontaktų skaičius ir vieno žmogaus grupės / lygiai (be telefono ir el. pašto)
select 'kontaktu' as k, count(*)::text as v from public.contacts;
select 'zmogus' as k, id || ' · ' || coalesce(data->>'first','') || ' ' || coalesce(data->>'last','') || ' · grupės ' || coalesce((data->'groups')::text,'') || ' · lygiai ' || coalesce((data->'levels')::text,'') as v
  from public.contacts where (coalesce(data->>'first','') || ' ' || coalesce(data->>'last','')) ilike '%jestrem%';
select 'grupes' as k, (value::text) as v from public.app_config where key in ('ev_opts','evOpts','options') limit 1;
