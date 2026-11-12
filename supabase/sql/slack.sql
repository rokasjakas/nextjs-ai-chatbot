-- ============================================================
-- Renginių kanalai Slack (serverio funkcija slack-sync)
--  * slack_channels – kuris renginys turi kurį Slack kanalą, briefo žinutė, kas jau pakviestas, kada archyvuota
--  * mato tie, kas mato Renginius; rašo tik serverio funkcija (service role)
--  * kasdien 05:47 (Vilniaus ~07:47): archyvuoja kanalus praėjus 7 d. po renginio (atšauktus – iš karto),
--    sukuria trūkstamus artėjantiems renginiams ir atnaujina briefą bei pakvietimus
--  * įjungiama Admin → Slack (app_config 'slack' = {"on": true}); be SLACK_BOT_TOKEN funkcija nieko nedaro
-- Paleidžiama per „SQL paleidimas“. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.slack_channels (
  event_id    text primary key,
  channel_id  text not null,
  name        text not null default '',
  url         text not null default '',
  brief_ts    text,
  invited     text[] not null default '{}',
  archived_at timestamptz,
  last_error  text,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
alter table public.slack_channels enable row level security;
drop policy if exists "slack view" on public.slack_channels;
create policy "slack view" on public.slack_channels for select to authenticated using (public.can_view('events'));
grant select on public.slack_channels to authenticated;
grant all on public.slack_channels to service_role;

-- the daily run, with the same CRON_SECRET as the other scheduled jobs
do $$
declare secret text;
begin
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
    from cron.job where command like '%x-cron-secret%' order by jobid limit 1;
  if secret is null then raise exception 'Nerasta suplanuotų užduočių su CRON_SECRET.'; end if;
  perform cron.unschedule(jobid) from cron.job where jobname = 'slack-sweep';
  perform cron.schedule('slack-sweep', '47 5 * * *', format($job$
    select net.http_post(
      url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/slack-sync',
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', %L),
      body    := '{"action":"sweep"}'::jsonb,
      timeout_milliseconds := 120000
    );
  $job$, secret));
end $$;

notify pgrst, 'reload schema';
select 'slack_channels' as k, count(*)::text as v from public.slack_channels
union all select 'slack-sweep', coalesce((select schedule || case when active then ' aktyvi' else ' išjungta' end from cron.job where jobname = 'slack-sweep'), 'nėra');
