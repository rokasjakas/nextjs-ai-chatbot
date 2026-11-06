-- ============================================================
-- „Išlaidos“: termino nebėra
--  * exp_month_open(d) visada leidžia: narys savo išlaidas ir UTA pylimų pagrindimus (asmeninis / darbo)
--    gali pateikti, taisyti ir trinti bet kada (anksčiau – tik iki kito mėnesio 10 d.)
--  * tvirtinti ir kompensaciją priskirti vis tiek gali tik Admin+ (expenses_rules.sql)
-- Reikia: expenses_rules.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create or replace function public.exp_month_open(d date) returns boolean
  language sql stable as $$
  select d is not null
$$;
grant execute on function public.exp_month_open(date) to authenticated;
notify pgrst, 'reload schema';
