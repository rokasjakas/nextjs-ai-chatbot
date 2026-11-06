-- ============================================================
-- Freelancerių sąskaitos (3): laiškas freelanceriui išeina pats
--  * kai portalo sąskaitos būsena pasikeičia (netvirtinta / patvirtinta / apmokėta),
--    duomenų bazė iškart kviečia „push-notify“ – laiškas išsiunčiamas nepriklausomai
--    nuo to, kokia programos versija atidaryta
--  * ext_mailed – kas jau pranešta (antras toks pat laiškas nesiunčiamas)
-- Reikia: freelance_portal.sql ir mail_viskas.sql (ar kitas cron su x-cron-secret).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create extension if not exists pg_net;
alter table public.invoices add column if not exists ext_mailed text;
create index if not exists invoices_ext_email_idx on public.invoices (ext_email) where source = 'portal';

create or replace function public.invoices_portal_mail() returns trigger
  language plpgsql security definer set search_path = public, extensions as $$
declare secret text;
begin
  if new.source is distinct from 'portal' or new.status is not distinct from old.status
     or new.status not in ('rejected','approved','sent','queued','paid') then
    return new;
  end if;
  -- the cron secret the scheduled jobs already use
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
    from cron.job where command like '%x-cron-secret%' order by jobid limit 1;
  if secret is null then return new; end if;
  perform net.http_post(
    url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/push-notify',
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', secret),
    body    := jsonb_build_object('mode', 'invoice-portal-status', 'invoice_id', new.id),
    timeout_milliseconds := 20000
  );
  return new;
exception when others then
  return new;   -- a letter that fails never blocks the decision
end $$;
revoke all on function public.invoices_portal_mail() from public, anon, authenticated;

drop trigger if exists invoices_portal_mail on public.invoices;
create trigger invoices_portal_mail after update of status on public.invoices
  for each row execute function public.invoices_portal_mail();

notify pgrst, 'reload schema';
