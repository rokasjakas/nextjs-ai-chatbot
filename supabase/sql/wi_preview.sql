-- Tik skaito: kiek darbų įrašų išimtų work_items_names.sql (narių įrašai ir to paties žmogaus dublikatai) – nieko nekeičia
create or replace function pg_temp.n(t text) returns text language sql immutable as $$
  select regexp_replace(translate(lower(coalesce(t, '')), 'ąčęėįšųūžéèàáóöüäõ', 'aceeisuuzeeaaoouao'), '[^a-z0-9]', '', 'g') $$;
with mem as (select w.id, w.person, w.edited from public.work_items w where w.auto_key is not null and w.invoice_id is null
  and exists (select 1 from public.profiles p where coalesce(p.role,'') in ('admin','pm','office','tech','runner')
    and pg_temp.n(w.person) in (pg_temp.n(p.full_name), pg_temp.n(coalesce(p.first_name,'')||coalesce(p.last_name,'')), pg_temp.n(coalesce(p.last_name,'')||coalesce(p.first_name,'')), coalesce(nullif(pg_temp.n(p.nickname),''),'-'))))
select 'nariu irasai (butu isimti)' as k, count(*)::text || ' · ' || coalesce(string_agg(distinct person, ', '), '') as v from mem where not edited
union all select 'nariu irasai taisyti ranka (liktu)', count(*)::text from mem where edited
union all select 'dublikatai (tas pats renginys, grupe, zmogus)', (select count(*) - count(distinct split_part(auto_key,'|',1)||'|'||split_part(auto_key,'|',2)||'|'||pg_temp.n(person)) from public.work_items where auto_key is not null)::text;
