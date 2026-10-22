-- ============================================================
-- Pradžios puslapio kortelė „Pranešimai“: kiekvieno nario pranešimai (žinutės,
-- paminėjimai, kalendorius, renginiai, užduotys, sąskaitos, įranga, prašymai…).
--  * įrašo funkcija push-notify – tą patį, ką siunčia į telefoną (net jei pranešimai
--    telefone išjungti); tas pats pranešimas (tag) tik atnaujinamas
--  * kiekvienas mato ir žymi perskaitytais tik savo; senesni nei 30 d. ištrinami
-- Po šio failo iš naujo įdiek funkciją push-notify.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.user_notifications (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users(id) on delete cascade,
  tag         text not null,
  kind        text,
  title       text not null default '',
  body        text not null default '',
  url         text not null default './',
  created_at  timestamptz not null default now(),
  read_at     timestamptz
);
create unique index if not exists user_notifications_tag on public.user_notifications (user_id, tag);
create index if not exists user_notifications_time on public.user_notifications (user_id, created_at desc);

alter table public.user_notifications enable row level security;
drop policy if exists "own notifications" on public.user_notifications;
create policy "own notifications" on public.user_notifications for select to authenticated using (user_id = auth.uid());
drop policy if exists "read own notifications" on public.user_notifications;
create policy "read own notifications" on public.user_notifications for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
drop policy if exists "remove own notifications" on public.user_notifications;
create policy "remove own notifications" on public.user_notifications for delete to authenticated using (user_id = auth.uid());
revoke all on public.user_notifications from anon;
grant select, update, delete on public.user_notifications to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';
