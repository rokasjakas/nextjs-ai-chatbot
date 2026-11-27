-- Augustino kuro balanso duomenys (tik skaitymas, be kontaktų)
create temp table t_u as select id from public.profiles where first_name ilike 'Augustin%' limit 1;
select 'allow' as k, monthly, start_month from public.expense_allowance where user_id = (select id from t_u);
select 'exp' as k, spent_on, paid, purpose, status, amount, liters, comp, uta_tx_id is not null as linked from public.expenses where user_id = (select id from t_u) and kind='fuel' order by spent_on;
select 'pers' as k, t.tx_date, t.country, t.amount_gross, t.amount_net, t.quantity from public.uta_personal p join public.uta_tx t on t.id = p.tx_id where p.user_id = (select id from t_u) order by t.tx_date;
select 'cards' as k, count(*) from public.uta_cards where assign_kind='person' and person_id = (select id from t_u);
select 'tx' as k, to_char(t.tx_date,'YYYY-MM') as m, count(*), sum(t.amount_gross) from public.uta_tx t join public.uta_cards c on c.id = t.card_id where c.person_id = (select id from t_u) group by 2 order by 2;
select 'use' as k, used_on, unit, amount, liters from public.comp_use where user_id = (select id from t_u);
select 'reports' as k, month, rows from public.uta_reports order by month desc limit 4;
