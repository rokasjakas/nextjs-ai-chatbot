-- Ištrintas pasiūlymas 884aea74… – ar yra, ir kas apie jį liko kataloge (tik skaitymas)
select 'live' as t, count(*) from public.offers where id = '884aea74-4b26-4bb6-9eed-9882d7bd9c16';
select 'deividas_today' as t, id, title, client, updated_at from public.offers where updated_by ilike '%deivid%' and updated_at > now() - interval '1 day' order by updated_at desc;
select 'cat' as t, data->>'kind' as kind, data->>'name' as name, data->>'price' as price, data->>'unit' as unit, updated_at from public.offer_catalog where data->'offers' ? '884aea74-4b26-4bb6-9eed-9882d7bd9c16' order by updated_at;
