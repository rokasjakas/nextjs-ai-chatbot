-- Tik skaito: darbų įrašų vardai, kurie skiriasi tik tarpais / raidėmis (galimi dublikatai), ir ar jie yra Žmonėse
with n as (select person, regexp_replace(translate(lower(person), 'ąčęėįšųūž', 'aceeisuuz'), '[^a-z0-9]', '', 'g') k, count(*) c from public.work_items group by person)
select 'vardai' as k, string_agg(person || ' (' || c || ')', ' | ' order by person) as v from n group by k having count(*) > 1;
select 'kontaktu laukai' as k, string_agg(distinct key, ', ') as v from public.contacts, jsonb_object_keys(data) key;
select 'be kontakto' as k, count(*)::text as v from public.work_items where contact_id is null;
select 'is viso' as k, count(*)::text as v from public.work_items;
