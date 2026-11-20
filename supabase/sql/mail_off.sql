-- ============================================================
-- „El. paštas“ puslapis pašalintas (v632). Lieka tik tai, kas susiję su sąskaitomis ir siuntimu:
--  * sąskaitų dėžutė saskaitos@ → „Sąskaitos“ – nauja užduotis „invoice-inbox“ kas 2 min. (naktį 22–7 – kas 10 min.);
--  * siuntimas iš savo pašto (renginio laiškas, sąskaitos buhalterijai) – prijungtas paštas (mail_accounts) lieka.
-- Išjungiama: pašto dėžučių sinchronizavimas (mail-sync, mail-sync-fast), automatinis atsakymas, Gmail skaitymas
-- ir įmonės pašto kopijavimas į Gmail; išvalomos laiškų kopijos ir sąrašai (mail_index, mail_bodies, mail_sync,
-- mail_in). Patys laiškai lieka jūsų pašto serveryje / Gmail – programa jų tiesiog nebelaiko.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
do $$
declare secret text;
begin
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
    from cron.job where jobname in ('mail-sync', 'mail-sync-fast', 'invoice-inbox', 'vehicle-reminders-daily') and command like '%x-cron-secret%' limit 1;
  if secret is null then raise exception 'Nerastas CRON_SECRET suplanuotose užduotyse.'; end if;

  perform cron.unschedule(jobid) from cron.job where jobname in ('mail-sync', 'mail-sync-fast', 'mail-auto-reply', 'invoice-inbox');
  perform cron.schedule('invoice-inbox', '*/2 * * * *', format($job$
    select net.http_post(
      url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/mail',
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', %L),
      body    := '{"action":"invoice_inbox"}'::jsonb,
      timeout_milliseconds := 110000
    ) where extract(hour from now() at time zone 'Europe/Vilnius') between 7 and 21
         or extract(minute from now())::int %% 10 = 0;
  $job$, secret));

  perform cron.unschedule(jobid) from cron.job where jobname = 'cron-log-cleanup';
  perform cron.schedule('cron-log-cleanup', '17 * * * *', $c$delete from cron.job_run_details where end_time < now() - interval '1 day'$c$);
end $$;

-- laiškų kopijos ir sąrašai – nebereikalingi
truncate table public.mail_index, public.mail_bodies, public.mail_sync;
do $$ begin if to_regclass('public.mail_in') is not null then execute 'truncate table public.mail_in'; end if; end $$;
-- siuntimui lieka tik pats paštas: Gmail skaitymo slaptažodis, automatinis atsakymas ir kopijavimo būsena ištrinami
update public.mail_accounts set reader = null, state = '{}'::jsonb, settings = coalesce(settings, '{}'::jsonb) - 'auto' - 'mirror';
delete from cron.job_run_details where end_time < now() - interval '1 day';

select jobname, schedule, active from cron.job order by jobname;
