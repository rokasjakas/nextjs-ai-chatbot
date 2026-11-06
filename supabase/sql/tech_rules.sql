-- ============================================================
-- Tech lygis nemato „Ataskaitos“; Runner gali įkelti savo sąskaitas ir matyti tik savo įkeltas
-- Transporte Tech, Freelance ir Runner tik žiūri automobilius ir jų dokumentus (tech. apžiūra, kelių mokestis…), nieko neprideda ir nekeičia.
-- (Admin skiltyje teises galima pakeisti bet kada).
-- Transporte Tech mato tik automobilius (Transporto nuoma ir UTA kortelės – tik
-- Admin, Office ir Projektų vadovams) – tai nustato programėlė.
-- Supabase → SQL Editor → New query → įklijuok → Run. Saugu paleisti pakartotinai.
-- ============================================================
insert into public.role_permissions (role, section, can_view, can_edit) values ('tech','stats',false,false)
on conflict (role, section) do update set can_view = false, can_edit = false;
insert into public.role_permissions (role, section, can_view, can_edit) values ('runner','invoices',true,true)
on conflict (role, section) do update set can_view = true, can_edit = true;
insert into public.role_permissions (role, section, can_view, can_edit) values ('tech','fleet',true,false), ('freelance','fleet',true,false), ('runner','fleet',true,false)
on conflict (role, section) do update set can_view = true, can_edit = false;
