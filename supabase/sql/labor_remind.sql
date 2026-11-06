-- Darbų apskaita (3 etapas): laukiamų sąskaitų priminimai. Kada kam priminta – prie darbo įrašo.
-- Siunčia push-notify (kasdien ~9 val.), tik kai įjungta Admin → „Darbų apskaita: sąskaitų priminimai“
-- (app_config „labor_remind“: {on, days, from}); pagal nutylėjimą išjungta.
alter table public.work_items add column if not exists reminded_at timestamptz;       -- freelanceriui
alter table public.work_items add column if not exists mgr_reminded_at timestamptz;   -- atsakingam
insert into public.app_config (key, value) values ('labor_remind', '{"on": false, "days": 14, "from": ""}'::jsonb)
  on conflict (key) do nothing;
notify pgrst, 'reload schema';
select 'laukia sąskaitos (atlikti, be sąskaitos)' as k, count(*)::text as v from public.work_items where status = 'done' and invoice_id is null
union all select 'priminimai', (select value::text from public.app_config where key = 'labor_remind');
