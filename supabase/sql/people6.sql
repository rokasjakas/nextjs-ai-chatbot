-- ============================================================
-- people6.sql — automatiniai Bookingo laiškai
--  * booking_reminders.auto — priminimas sukurtas automatiškai pažymėjus „Sutiko“:
--    iškart laiškas žmogui ir tam, kas bookino (reply_to), vėliau – tik dieną prieš
--    kiekvieną darbo dieną 10:00 (Lietuvos laiku), abiem.
-- Saugu paleisti pakartotinai.
-- ============================================================
alter table public.booking_reminders add column if not exists auto boolean not null default false;
notify pgrst, 'reload schema';
