-- Pasiūlymų archyvo patikra transakcijoje, kuri atšaukiama (rollback) – tikri duomenys nepakeičiami
begin;
create temp table t_o as select id from public.offers where jsonb_array_length(coalesce(data->'versions','[]'::jsonb)) >= 2 order by updated_at desc limit 1;
select 'pick' as k, (select id from t_o) as id, (select jsonb_array_length(data->'versions') from public.offers where id = (select id from t_o)) as vers;
-- remove the last version
update public.offers set data = jsonb_set(data, '{versions}', (data->'versions') - (jsonb_array_length(data->'versions') - 1)) where id = (select id from t_o);
select 'after_ver' as k, kind, versions, data->>'name' as vname from public.offers_archive where offer_id = (select id from t_o) order by id;
delete from public.offers where id = (select id from t_o);
select 'after_del' as k, kind, title from public.offers_archive where offer_id = (select id from t_o) order by id;
-- offer_restore checks the rights of the signed in member (none here) – the error is expected
select 'live_gone' as k, count(*) from public.offers where id = (select id from t_o);
rollback;
select 'archive_rows_after_rollback' as k, count(*) from public.offers_archive;
