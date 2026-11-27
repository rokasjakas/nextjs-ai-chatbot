-- ============================================================
-- reminders_cfg.sql — Admin → Priminimai: visų priminimų bendri nustatymai (app_config raktas 'reminders')
--  * {tipas: {off, hour, days[], every, title, text, only[], skip[], copy}} – nuskaito serverio funkcijos
--    (push-notify, booking-reminders, vehicle-reminders, slack-sync, reports-mail)
--  * keisti gali Admin (ir aukštesni) per reminders_cfg_set; kiekvienas pakeitimas – app_config_log
-- Reikia: app_config.sql. Saugu paleisti pakartotinai.
-- ============================================================
create or replace function public.reminders_cfg_set(p_value jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare me public.profiles; old jsonb; who text;
begin
  select * into me from public.profiles where id = auth.uid();
  if me.id is null or not public.is_admin() then return jsonb_build_object('error', 'Priminimus keisti gali tik Admin.'); end if;
  if p_value is null or jsonb_typeof(p_value) <> 'object' then return jsonb_build_object('error', 'Reikšmė turi būti objektas.'); end if;
  if pg_column_size(p_value) > 100000 then return jsonb_build_object('error', 'Per dideli nustatymai.'); end if;
  who := nullif(btrim(coalesce(me.first_name, '')||' '||coalesce(me.last_name, '')), '');
  select value into old from public.app_config where key = 'reminders';
  insert into public.app_config (key, value, updated_at, updated_by, updated_name) values ('reminders', p_value, now(), me.id, who)
    on conflict (key) do update set value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by, updated_name = excluded.updated_name;
  insert into public.app_config_log (key, value, prev, by, name, note) values ('reminders', p_value, old, me.id, who, 'Admin → Priminimai');
  return (select to_jsonb(c) from public.app_config c where key = 'reminders');
end $$;
revoke all on function public.reminders_cfg_set(jsonb) from public, anon;
grant execute on function public.reminders_cfg_set(jsonb) to authenticated;
notify pgrst, 'reload schema';
