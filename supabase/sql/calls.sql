-- ============================================================
-- Vaizdo skambučiai chate (Google Meet arba Daily.co):
--  * calls           — skambutis pokalbyje (kas skambina, Meet nuoroda)
--  * call_responses  — kiekvieno nario atsakymas: priėmė / atmetė
--  * google_meet_auth — prijungtos Google paskyros raktas (užšifruotas);
--    jį mato tik serverio funkcija „meet“, programėlė — ne.
-- Paleisti PO chat_slack.sql. Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.calls (
  id              uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  created_by      uuid not null default auth.uid() references auth.users(id) on delete cascade,
  meet_url        text not null,
  created_at      timestamptz not null default now(),
  ended_at        timestamptz
);
-- vaizdo skambučio paslauga: Google Meet (atskiras langas) arba Daily.co (chate)
alter table public.calls add column if not exists provider text not null default 'meet';
alter table public.calls add column if not exists room text;
alter table public.calls drop constraint if exists calls_meet_url_check;
alter table public.calls drop constraint if exists calls_url_check;
alter table public.calls add constraint calls_url_check check (
  (provider = 'meet' and meet_url ~ '^https://meet\.google\.com/[a-z0-9-]+$')
  or (provider = 'daily' and meet_url ~ '^https://[a-z0-9-]+\.daily\.co/[A-Za-z0-9_-]+$'));
alter table public.calls drop constraint if exists calls_provider_check;
alter table public.calls add constraint calls_provider_check check (provider in ('meet','daily'));
create index if not exists calls_conv_idx on public.calls (conversation_id, created_at desc);

alter table public.calls enable row level security;
drop policy if exists "see calls" on public.calls;
create policy "see calls" on public.calls
  for select to authenticated using (public.is_conv_member(conversation_id));
drop policy if exists "start call" on public.calls;
create policy "start call" on public.calls
  for insert to authenticated with check (
    -- Daily kambarius kuria tik serverio funkcija „meet“ (ji tikrina narystę)
    created_by = auth.uid() and provider = 'meet' and public.is_conv_member(conversation_id)
    and (exists (select 1 from public.conversations c where c.id = conversation_id and c.kind = 'general')
         or exists (select 1 from public.conversation_members m where m.conversation_id = calls.conversation_id and m.user_id = auth.uid())));
drop policy if exists "end own call" on public.calls;
create policy "end own call" on public.calls
  for update to authenticated using (created_by = auth.uid()) with check (created_by = auth.uid());
-- skambučio kūrėjas gali tik jį užbaigti (nuorodos ar kambario pakeisti negalima)
revoke update on public.calls from authenticated;
grant update (ended_at) on public.calls to authenticated;

create table if not exists public.call_responses (
  call_id    uuid not null references public.calls(id) on delete cascade,
  user_id    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  status     text not null check (status in ('accepted','declined')),
  created_at timestamptz not null default now(),
  primary key (call_id, user_id)
);
alter table public.call_responses enable row level security;
drop policy if exists "see call answers" on public.call_responses;
create policy "see call answers" on public.call_responses
  for select to authenticated using (
    exists (select 1 from public.calls c where c.id = call_id and public.is_conv_member(c.conversation_id)));
drop policy if exists "answer call" on public.call_responses;
create policy "answer call" on public.call_responses
  for insert to authenticated with check (
    user_id = auth.uid()
    and exists (select 1 from public.calls c where c.id = call_id and public.is_conv_member(c.conversation_id)));
drop policy if exists "change answer" on public.call_responses;
create policy "change answer" on public.call_responses
  for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- Google paskyra: RLS įjungta be taisyklių — pasiekia tik serverio funkcija
create table if not exists public.google_meet_auth (
  id            int primary key default 1 check (id = 1),
  refresh_token text not null,
  email         text not null default '',
  connected_by  uuid references auth.users(id) on delete set null,
  connected_at  timestamptz not null default now()
);
alter table public.google_meet_auth enable row level security;

-- skambučiai ir atsakymai ateina realiu laiku
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'calls') then
      execute 'alter publication supabase_realtime add table public.calls';
    end if;
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'call_responses') then
      execute 'alter publication supabase_realtime add table public.call_responses';
    end if;
  end if;
end $$;
