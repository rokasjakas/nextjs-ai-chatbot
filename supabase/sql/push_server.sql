-- ============================================================
-- Chato pranešimai siunčia serveris (ne siuntėjo programėlė)
--  * kiekviena nauja chato žinutė (programoje, per QR, automatinė) duomenų bazėje iškart
--    kviečia „push-notify“ – pranešimas į telefoną ir kompiuterį išeina net jei siuntėjas
--    tuoj pat uždarė programėlę ar dingo ryšys
--  * message_push – kurios žinutės jau praneštos: programėlė vis dar klausia ir pati,
--    bet pranešimas išeina tik vieną kartą (kas pirmesnis)
--  * susitikimų svečių žinutės (guest_id) kaip ir anksčiau – per funkciją „guest“
-- Reikia: pg_net ir suplanuotų užduočių (cron) su x-cron-secret (mail_viskas.sql ar kt.).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create extension if not exists pg_net;

create table if not exists public.message_push (
  message_id uuid primary key,
  at         timestamptz not null default now()
);
alter table public.message_push enable row level security;
revoke all on public.message_push from anon, authenticated;

create or replace function public.messages_push_notify() returns trigger
  language plpgsql security definer set search_path = public, extensions as $$
declare secret text;
begin
  if new.deleted_at is not null or coalesce(to_jsonb(new) ->> 'guest_id', '') <> '' then return new; end if;
  -- the cron secret the scheduled jobs already use
  select substring(command from 'x-cron-secret''\s*,\s*''([^'']+)''') into secret
    from cron.job where command like '%x-cron-secret%' order by jobid limit 1;
  if secret is null then return new; end if;
  perform net.http_post(
    url     := 'https://yakmikxkcudwloxruhvx.supabase.co/functions/v1/push-notify',
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', secret),
    body    := jsonb_build_object('mode', 'message-db', 'message_id', new.id),
    timeout_milliseconds := 20000
  );
  return new;
exception when others then
  return new;   -- a notification that fails never blocks the message
end $$;
revoke all on function public.messages_push_notify() from public, anon, authenticated;

drop trigger if exists messages_push_notify on public.messages;
create trigger messages_push_notify after insert on public.messages
  for each row execute function public.messages_push_notify();

notify pgrst, 'reload schema';
