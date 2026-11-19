-- Išlaidos – patikra (tik skaitymas): purpose stulpelis, uta_personal stulpeliai, expense_set_purpose funkcija
select 'col' as k, column_name, column_default from information_schema.columns where table_schema='public' and table_name='expenses' and column_name='purpose';
select 'chk' as k, conname from pg_constraint where conrelid='public.expenses'::regclass and conname='expenses_purpose_check';
select 'up' as k, column_name, data_type from information_schema.columns where table_schema='public' and table_name='uta_personal' order by ordinal_position;
select 'fn' as k, proname from pg_proc where proname in ('expense_set_purpose','expense_deduct');
select 'cnt' as k, purpose, count(*) from public.expenses group by purpose;
