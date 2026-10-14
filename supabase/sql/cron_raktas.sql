-- ============================================================
-- Suplanuotų užduočių raktas (CRON_SECRET) iš naujo
--  Kai Supabase slaptas CRON_SECRET nebesutampa su raktu suplanuotose užduotyse,
--  visos jos gauna „Unauthorized“ (401): nesisinchronizuoja paštas, neišeina
--  laiškai freelanceriams, priminimai.
--  Šis SQL sukuria NAUJĄ atsitiktinį raktą, įrašo jį į visas užduotis ir parodo jį.
-- Po paleidimo (PC, projekto aplanke):
--     npx.cmd supabase secrets set CRON_SECRET=<parodytas raktas>
-- Raktas lieka tik tavo Supabase – niekur jo nesiųsk ir nekelk į GitHub.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run.
-- ============================================================
do $$
declare old_s text; new_s text; j record; n int := 0;
begin
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into old_s
    from cron.job where command like '%x-cron-secret%' order by jobid limit 1;
  if old_s is null then raise exception 'Nerasta suplanuotų užduočių su x-cron-secret.'; end if;
  new_s := replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');
  for j in select jobid, command from cron.job where position(old_s in command) > 0 loop
    perform cron.alter_job(j.jobid, command := replace(j.command, old_s, new_s));
    n := n + 1;
  end loop;
  create temp table if not exists _cron_raktas (raktas text, uzduociu int);
  delete from _cron_raktas;
  insert into _cron_raktas values (new_s, n);
end $$;
select raktas as "NAUJAS CRON_SECRET (nukopijuok)", uzduociu as "pakeista užduočių" from _cron_raktas;
