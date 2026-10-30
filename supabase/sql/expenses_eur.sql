-- ============================================================
-- Išlaidos: balansas asmeninėms reikmėms – tik eurais
-- (pvz. 200 € per mėnesį; asmeniniai UTA pylimai atimami jų suma eurais; nepanaudotas likutis pereina
-- į kitą mėnesį, viršytas – atimamas iš kito). Anksčiau litrais nustatyti balansai ir pažymėti
-- asmeniniai pylimai perjungiami į eurus (balanso skaičius lieka tas pats – patikrink, ar tinka).
-- Reikia: expenses_rules.sql, expenses_liters.sql. Saugu paleisti pakartotinai.
-- ============================================================
update public.expense_allowance set unit = 'eur' where unit is distinct from 'eur';
update public.uta_personal set unit = 'eur' where unit is distinct from 'eur';
alter table public.expense_allowance alter column unit set default 'eur';
alter table public.uta_personal alter column unit set default 'eur';
notify pgrst, 'reload schema';
