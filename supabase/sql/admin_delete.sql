-- ============================================================
-- Admin gali visam laikui ištrinti narį (Admin → vartotojų sąrašas → 🗑).
-- Kartu ištrinamas profilis, jo žinutės, reakcijos, užduotys, jo sukurti
-- susitikimai, pašto prisijungimas ir pranešimų įrenginiai.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================
create or replace function public.admin_delete_user(uid uuid) returns void
  language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_admin() then raise exception 'Tik administratorius gali trinti narius.'; end if;
  if uid = auth.uid() then raise exception 'Savęs ištrinti negalima.'; end if;
  if (select role from public.profiles where id = uid) = 'admin'
     and (select count(*) from public.profiles where role = 'admin') <= 1 then
    raise exception 'Negalima ištrinti paskutinio administratoriaus.';
  end if;
  -- iš susitikimų, į kuriuos jis buvo pakviestas
  update public.meetings set attendees = array_remove(attendees, uid) where uid = any(attendees);
  delete from auth.users where id = uid;
end $$;
revoke all on function public.admin_delete_user(uuid) from public, anon;
grant execute on function public.admin_delete_user(uuid) to authenticated;
