-- ============================================================
-- „Games“: žaidimų rezultatai (rekordų lentelė)
--  * vienam: kiekvienas rezultatas – eilutė, lentelėje rodomas geriausias
--  * keliese: kiekviena pergalė – eilutė su score = 1 (sumuojama)
--  * mato visi prisijungę, įrašo tik savo vardu
-- Žaidimai keliese naudoja Supabase Realtime (broadcast) – lentelių nereikia.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.game_scores (
  id         bigint generated always as identity primary key,
  user_id    uuid not null default auth.uid(),
  name       text not null default '',
  game       text not null,
  score      integer not null check (score > 0 and score < 100000000),
  created_at timestamptz not null default now()
);
create index if not exists game_scores_game on public.game_scores (game, score desc);

alter table public.game_scores enable row level security;
drop policy if exists "view game_scores" on public.game_scores;
create policy "view game_scores" on public.game_scores
  for select to authenticated using (true);
drop policy if exists "add game_scores" on public.game_scores;
create policy "add game_scores" on public.game_scores
  for insert to authenticated with check (user_id = auth.uid());
grant select, insert on public.game_scores to authenticated;
