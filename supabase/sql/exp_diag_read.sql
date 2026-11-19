-- Išlaidos – patikra (tik skaitymas): ar yra purpose stulpelis, apribojimai, trigeriai, paskutinės asmeninės / UTA išlaidos
select 'col' as k, column_name, data_type, column_default from information_schema.columns where table_schema='public' and table_name='expenses' order by ordinal_position;
select 'chk' as k, conname, pg_get_constraintdef(oid) from pg_constraint where conrelid='public.expenses'::regclass;
select 'trg' as k, tgname, pg_get_triggerdef(oid) from pg_trigger where tgrelid='public.expenses'::regclass and not tgisinternal;
select 'fn' as k, p.proname, left(regexp_replace(pg_get_functiondef(p.oid), '\s+', ' ', 'g'), 1500) from pg_proc p join pg_trigger t on t.tgfoid=p.oid where t.tgrelid='public.expenses'::regclass and not t.tgisinternal;
select 'row' as k, kind, paid, purpose, status, updated_at from public.expenses order by updated_at desc nulls last limit 5;
