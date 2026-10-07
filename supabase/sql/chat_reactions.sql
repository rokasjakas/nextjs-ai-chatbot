-- ============================================================
-- Reakcijos į žinutes (👍 ❤️ 😂 …). Paleisti PO members_chat.sql.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.message_reactions (
  message_id uuid not null references public.messages(id) on delete cascade,
  user_id    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  emoji      text not null check (char_length(emoji) between 1 and 16),
  created_at timestamptz not null default now(),
  primary key (message_id, user_id, emoji)
);
create index if not exists message_reactions_msg_idx on public.message_reactions (message_id);

-- ar vartotojas mato žinutę (yra to pokalbio narys)
create or replace function public.can_see_message(mid uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.messages m where m.id = mid and public.is_conv_member(m.conversation_id))
$$;
grant execute on function public.can_see_message(uuid) to authenticated;

alter table public.message_reactions enable row level security;
drop policy if exists "see reactions" on public.message_reactions;
create policy "see reactions" on public.message_reactions
  for select to authenticated using (public.can_see_message(message_id));
drop policy if exists "add own reaction" on public.message_reactions;
create policy "add own reaction" on public.message_reactions
  for insert to authenticated with check (user_id = auth.uid() and public.can_see_message(message_id));
drop policy if exists "remove own reaction" on public.message_reactions;
create policy "remove own reaction" on public.message_reactions
  for delete to authenticated using (user_id = auth.uid());

-- reakcijos realiu laiku (ištrynimo įvykyje reikia visų stulpelių)
alter table public.message_reactions replica identity full;
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'message_reactions') then
    execute 'alter publication supabase_realtime add table public.message_reactions';
  end if;
end $$;
