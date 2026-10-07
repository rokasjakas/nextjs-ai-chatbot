-- ============================================================
-- El. paštas: automatinis atsakymas („ne biure“) – kas minutę, ne kas 10 min.
--  * atsakymai dabar siunčiami kartu su pašto tikrinimu („mail-sync“, kas minutę),
--    todėl senas 10 minučių darbas išjungiamas (kad neatsakytų du kartus)
-- Reikia: „mail“ funkcija v22.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
select cron.unschedule(jobid) from cron.job where jobname = 'mail-auto-reply';
select jobname, schedule, active from cron.job where jobname like 'mail%';
