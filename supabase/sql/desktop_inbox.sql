-- ============================================================
-- Windows programa (Event Solutions .exe): pranešimai kompiuteryje
--  * Web Push kompiuterio programoje neveikia, todėl push-notify kiekvieną
--    pranešimą dar įrašo į desktop_inbox tiems, kas naudoja programą
--    (desktop_clients – kas ir kada paskutinį kartą ją atidarė)
--  * programa klauso savo eilučių (Realtime) ir rodo Windows pranešimą
--  * senesni nei 3 d. įrašai ištrinami automatiškai
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.desktop_clients (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  last_seen  timestamptz not null default now()
);
alter table public.desktop_clients enable row level security;
drop policy if exists "desktop clients own" on public.desktop_clients;
create policy "desktop clients own" on public.desktop_clients for select to authenticated using (user_id = auth.uid());
revoke all on public.desktop_clients from anon, authenticated;
grant select on public.desktop_clients to authenticated;

create table if not exists public.desktop_inbox (
  id          bigint generated always as identity primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  title       text not null default '',
  body        text not null default '',
  tag         text,
  url         text,
  kind        text,
  created_at  timestamptz not null default now()
);
create index if not exists desktop_inbox_user on public.desktop_inbox (user_id, id);
create index if not exists desktop_inbox_age on public.desktop_inbox (created_at);
alter table public.desktop_inbox enable row level security;
drop policy if exists "desktop inbox own" on public.desktop_inbox;
create policy "desktop inbox own" on public.desktop_inbox for select to authenticated using (user_id = auth.uid());
revoke all on public.desktop_inbox from anon, authenticated;
grant select on public.desktop_inbox to authenticated;

-- programa praneša, kad šis narys ją naudoja (kviečiama ją atidarius)
create or replace function public.desktop_register() returns void
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or not public.is_approved() then return; end if;
  insert into public.desktop_clients (user_id, last_seen) values (auth.uid(), now())
    on conflict (user_id) do update set last_seen = now();
end $$;
revoke all on function public.desktop_register() from public, anon;
grant execute on function public.desktop_register() to authenticated;

-- nauji pranešimai iš karto (Realtime)
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'desktop_inbox') then
    execute 'alter publication supabase_realtime add table public.desktop_inbox';
  end if;
end $$;
