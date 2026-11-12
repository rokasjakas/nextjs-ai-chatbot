-- ============================================================
-- iPhone programa (TestFlight): Apple pranešimų (APNs) įrenginiai
--  * programa perduoda puslapiui savo įrenginio raktą, puslapis jį
--    užregistruoja (ios_register); push-notify siunčia į visus nario įrenginius
--  * Apple atsakius, kad raktas nebegalioja, push-notify jį ištrina
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.ios_devices (
  token      text primary key check (token ~ '^[0-9a-f]{64,200}$'),
  user_id    uuid not null references auth.users(id) on delete cascade,
  updated_at timestamptz not null default now()
);
create index if not exists ios_devices_user on public.ios_devices (user_id);
alter table public.ios_devices enable row level security;
drop policy if exists "ios devices own" on public.ios_devices;
create policy "ios devices own" on public.ios_devices for select to authenticated using (user_id = auth.uid());
revoke all on public.ios_devices from anon, authenticated;
grant select on public.ios_devices to authenticated;

-- this iPhone belongs to the one signed in now (a phone can change hands)
create or replace function public.ios_register(p_token text) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or not public.is_approved() then return; end if;
  if p_token !~ '^[0-9a-f]{64,200}$' then raise exception 'bad token'; end if;
  insert into public.ios_devices (token, user_id, updated_at) values (p_token, auth.uid(), now())
    on conflict (token) do update set user_id = auth.uid(), updated_at = now();
end $$;
create or replace function public.ios_unregister(p_token text) returns void
  language sql security definer set search_path = public as $$
  delete from public.ios_devices where token = p_token and user_id = auth.uid();
$$;
revoke all on function public.ios_register(text) from public, anon;
revoke all on function public.ios_unregister(text) from public, anon;
grant execute on function public.ios_register(text) to authenticated;
grant execute on function public.ios_unregister(text) to authenticated;
