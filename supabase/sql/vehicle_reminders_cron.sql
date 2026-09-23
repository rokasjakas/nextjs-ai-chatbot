-- ============================================================
-- Kasdien 09:00 Lietuvos laiku (06:00 UTC) patikrina automobilių dokumentus
-- ir išsiunčia priminimus. PAKEISK_SLAPTAZODI pakeisk tuo pačiu tekstu,
-- kurį nustatei CRON_SECRET (supabase secrets set CRON_SECRET=...).
-- ============================================================
create extension if not exists pg_cron;
create extension if not exists pg_net;

select cron.schedule(
  'vehicle-reminders-daily',
  '0 6 * * *',
  $$
  select net.http_post(
    url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/vehicle-reminders',
    headers := jsonb_build_object('Content-Type', 'application/json',
                                  'x-cron-secret', 'PAKEISK_SLAPTAZODI'),
    body    := '{"mode":"cron"}'::jsonb
  );
  $$
);
