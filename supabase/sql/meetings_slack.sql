-- Susitikimai kalendoriuje: bendri (visa komanda – Slack #general) ir privatūs (atrinkti nariai – uždaras Slack kanalas).
-- Nariams – laiškas su kalendoriaus kvietimu (Google kalendoriui), Slack'e – pranešimas ir priminimai:
-- dieną prieš 10:00, tą dieną 1 val., 30, 15 ir 5 min. prieš (slack-sync „meet_tick“ kas minutę). Saugu paleisti pakartotinai.
alter table public.meetings add column if not exists scope text not null default '';
alter table public.meetings drop constraint if exists meetings_scope_check;
alter table public.meetings add constraint meetings_scope_check check (scope in ('', 'all', 'private'));
alter table public.meetings add column if not exists slack jsonb not null default '{}'::jsonb;   -- { channel, ts, private, sent:[…] } (tvarko funkcija)
-- the reminders: every minute (the same CRON_SECRET as the daily Slack run)
do $$ declare secret text; begin
  if not exists (select 1 from pg_extension where extname = 'pg_cron') then return; end if;
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret from cron.job where jobname = 'slack-sweep';
  if secret is null then raise notice 'Nėra slack-sweep užduoties – priminimai neplanuojami.'; return; end if;
  perform cron.unschedule(jobid) from cron.job where jobname = 'meeting-reminders';
  perform cron.schedule('meeting-reminders', '* * * * *', format($job$
    select net.http_post(
      url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/slack-sync',
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', %L),
      body    := '{"action":"meet_tick"}'::jsonb,
      timeout_milliseconds := 30000
    );
  $job$, secret));
end $$;
notify pgrst, 'reload schema';
select 'meetings.scope' as k, count(*)::text as v from information_schema.columns where table_schema = 'public' and table_name = 'meetings' and column_name in ('scope', 'slack')
union all select 'cron meeting-reminders', count(*)::text from cron.job where jobname = 'meeting-reminders';
