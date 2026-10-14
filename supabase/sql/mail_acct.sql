-- ============================================================
-- El. paštas: „Visi / Darbo / Asmeniniai“ – kiekvienas laiškas pažymimas, ar jis darbo
-- (gavėjas arba kopija – …@eventsolutions.lt; išsiųstuose – siuntėjas). Seni laiškai pažymimi
-- automatiškai per kelias minutes. Reikia: mail_viskas.sql ir „mail“ funkcija v19.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.mail_index add column if not exists acct text;
alter table public.mail_index add column if not exists snippet text;
create index if not exists mail_index_acct on public.mail_index (user_id, folder, acct, date desc nulls last);
notify pgrst, 'reload schema';
