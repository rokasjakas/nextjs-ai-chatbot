-- ============================================================
-- Freelancerių sąskaitos (4)
--  * ext_mail_log – paskutinio laiško freelanceriui rezultatas (programoje matosi, ar išėjo)
--  * file_total / file_check – kokia suma rasta įkeltame sąskaitos faile (tikrina AI)
--  * fl_portal_sessions.scans – jau perskaitytų failų sumos (tas pats failas neskaitomas du kartus)
-- Reikia: freelance_portal.sql, freelance_portal3.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.invoices add column if not exists ext_mailed   text;
alter table public.invoices add column if not exists ext_mail_log jsonb;
alter table public.invoices add column if not exists file_total   numeric(12,2);
alter table public.invoices add column if not exists file_check   text;
alter table public.fl_portal_sessions add column if not exists scans jsonb not null default '{}'::jsonb;
notify pgrst, 'reload schema';
