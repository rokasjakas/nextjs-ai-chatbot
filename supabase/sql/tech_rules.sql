-- ============================================================
-- Tech lygis nemato „Ataskaitos“ (Admin skiltyje teises galima pakeisti bet kada).
-- Transporte Tech mato tik automobilius (Transporto nuoma ir UTA kortelės – tik
-- Admin, Office ir Projektų vadovams) – tai nustato programėlė.
-- Supabase → SQL Editor → New query → įklijuok → Run. Saugu paleisti pakartotinai.
-- ============================================================
insert into public.role_permissions (role, section, can_view, can_edit) values ('tech','stats',false,false)
on conflict (role, section) do update set can_view = false, can_edit = false;
