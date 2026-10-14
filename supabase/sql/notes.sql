-- ============================================================
-- „Notes“: asmeniniai užrašai (Užduotys, Skaičiuotuvas)
--  * vienas užrašų lapas kiekvienam žmogui ir vietai (key: 'tasks', 'calc')
--  * mato ir keičia tik pats žmogus
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.user_notes (
  id         text primary key,               -- '<user_id>:<key>'
  user_id    uuid not null default auth.uid(),
  key        text not null,
  body       text not null default '',
  updated_at timestamptz not null default now()
);
create index if not exists user_notes_user on public.user_notes (user_id);

alter table public.user_notes enable row level security;
drop policy if exists "own notes" on public.user_notes;
create policy "own notes" on public.user_notes
  for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid() and id = auth.uid()::text || ':' || key);
grant select, insert, update, delete on public.user_notes to authenticated;
