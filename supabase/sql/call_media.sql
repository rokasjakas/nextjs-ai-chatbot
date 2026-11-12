-- ============================================================
-- Chato skambučiai: vaizdo arba garso (Daily.co)
--  * media 'video' – su kamera, 'audio' – tik garsas (kameras galima įsijungti)
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.calls add column if not exists media text not null default 'video';
alter table public.calls drop constraint if exists calls_media_check;
alter table public.calls add constraint calls_media_check check (media in ('video','audio'));
