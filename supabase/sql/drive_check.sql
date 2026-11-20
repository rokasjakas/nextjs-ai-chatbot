-- Tik skaito: renginių Drive aplankai – kam suteikta prieiga, klaidos; Office+ narių el. paštai
select 'aplankas' as k, event_id || ' · ' || name || ' · bendrinta: ' || coalesce(array_length(shared, 1), 0)::text || ' · ' || array_to_string(shared, ', ') || ' · klaida: ' || coalesce(left(last_error, 300), '') as v from public.event_drive order by created_at desc limit 5;
select 'office+' as k, string_agg(email, ', ') as v from public.profiles where role in ('admin','pm','office');
