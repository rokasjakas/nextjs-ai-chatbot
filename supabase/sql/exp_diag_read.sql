-- Pasiūlymo „Pristatymas“ (Kristina) pėdsakai kitose lentelėse – tik skaitymas
select 'jobs' as t, left(row_to_json(j)::text, 400) from public.jobs j where row_to_json(j)::text ilike '%pristatym%' and row_to_json(j)::text ilike '%kristin%' limit 5;
select 'jobs_today' as t, left(row_to_json(j)::text, 300) from public.jobs j where row_to_json(j)::text ilike '%2026-11-19%' limit 10;
select 'mail' as t, left(row_to_json(m)::text, 300) from public.mail_index m where row_to_json(m)::text ilike '%pristatym%' and row_to_json(m)::text ilike '%2026-11-1%' limit 5;
select 'err' as t, left(row_to_json(e)::text, 300) from public.app_errors e where row_to_json(e)::text ilike '%offer%' and row_to_json(e)::text ilike '%2026-11-19%' limit 5;
select 'cat' as t, id, updated_by, updated_at, left(data::text, 200) from public.offer_catalog where updated_at > now() - interval '1 day' order by updated_at desc limit 15;
