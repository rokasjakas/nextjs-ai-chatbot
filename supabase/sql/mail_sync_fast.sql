-- ============================================================
-- El. paštas: nauji laiškai tikrinami kas 15 sekundžių (ne kas minutę)
--  * „mail-sync-fast“ – greitas patikrinimas: ar atėjo naujų laiškų (+ pranešimas telefone
--    ir kompiuteryje), paruošiami keli naujausi; pilnas tikrinimas („mail-sync“) lieka kas minutę
-- Reikia: mail_viskas.sql (jau paleistas – „mail-sync“ veikia) ir „mail“ funkcija v17.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
do $$
declare secret text;
begin
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
    from cron.job where jobname = 'mail-sync';
  if secret is null then
    select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
      from cron.job where jobname = 'vehicle-reminders-daily';
  end if;
  if secret is null then raise exception 'Nerastas CRON_SECRET – pirmiausia paleisk mail_viskas.sql.'; end if;
  perform cron.unschedule(jobid) from cron.job where jobname = 'mail-sync-fast';
  perform cron.schedule('mail-sync-fast', '15 seconds', format($job$
    select net.http_post(
      url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/mail',
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', %L),
      body    := '{"action":"sync_all","quick":true}'::jsonb,
      timeout_milliseconds := 30000
    );
  $job$, secret));
end $$;
select jobname, schedule, active from cron.job where jobname like 'mail-sync%';

-- laiškų sąraše po tema – teksto pradžia (kaip Gmail)
alter table public.mail_index add column if not exists snippet text;
notify pgrst, 'reload schema';
