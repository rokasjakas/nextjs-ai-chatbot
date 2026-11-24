-- ============================================================
-- meetings_gcal.sql — susitikimai kaip tikri Google Calendar įvykiai
--  * google_meet_auth.scope – kokius leidimus davė prijungta Google paskyra (reikia calendar.events)
--  * meetings.gcal – to susitikimo Google Calendar įvykis {id, link, meet} (kad pakeitus / atšaukus būtų atnaujintas)
-- Saugu paleisti pakartotinai.
-- ============================================================
alter table public.google_meet_auth add column if not exists scope text;
alter table public.meetings add column if not exists gcal jsonb not null default '{}'::jsonb;
notify pgrst, 'reload schema';
