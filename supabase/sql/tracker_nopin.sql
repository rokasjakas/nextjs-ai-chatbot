-- ============================================================
-- Team Tracker be PIN kodo ir be registracijos
--  * kiekvienas patvirtintas programėlės narys naudojasi Team Tracker savo paskyra – PIN nebereikia
--  * atidarius Team Tracker narys sukuriamas automatiškai (vardas ir pavardė – iš profilio);
--    jau užregistruotas narys su tuo pačiu vardu ir pavarde susiejamas su paskyra
--  * savo laiką narys valdo tik savo paskyra; kitų laiką, kaip ir anksčiau, mato Admin, Office, Projektų vadovai
--  * demo darbuotojo laiką gali peržiūrėti visi
-- Reikia: tracker.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- the member tied to the signed-in account is always allowed; a key (token) from older devices still works
create or replace function public.tt_auth(m uuid, p_pin text, p_token text, admin_ok boolean) returns text
  language plpgsql security definer set search_path = public, extensions as $$
declare r public.tracker_members;
begin
  if auth.uid() is null or not public.is_approved() then return 'Reikia prisijungti prie programėlės.'; end if;
  select * into r from public.tracker_members where id = m;
  if r.id is null then return 'Tokio nario nėra.'; end if;
  if r.user_id = auth.uid() then return null; end if;
  if p_token is not null and exists (select 1 from public.tracker_tokens where member_id = m and token_hash = encode(digest(p_token, 'sha256'), 'hex')) then return null; end if;
  -- looking at the time: Admin / Office / Projektų vadovas – anyone's; everyone – the demo
  if admin_ok and (public.tt_manager() or r.demo) then return null; end if;
  return 'Savo laiką gali tvarkyti tik pats narys.';
end $$;
revoke all on function public.tt_auth(uuid, text, text, boolean) from public, anon, authenticated;

-- my member: found or made on first use
create or replace function public.tt_me() returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare mid uuid; nm text; base text; n int := 1; e text;
begin
  if auth.uid() is null or not public.is_approved() then return jsonb_build_object('error', 'Reikia prisijungti prie programėlės.'); end if;
  select id into mid from public.tracker_members where user_id = auth.uid();
  if mid is null then
    select nullif(btrim(coalesce(first_name,'') || ' ' || coalesce(last_name,'')), ''), email into base, e from public.profiles where id = auth.uid();
    base := coalesce(base, nullif(split_part(coalesce(e, ''), '@', 1), ''), 'Narys');
    -- a member registered earlier with the same name and not tied to anyone: it is mine
    select min(id::text)::uuid into mid from public.tracker_members
      where user_id is null and not demo and lower(btrim(name)) = lower(base)
      having count(*) = 1;
    if mid is not null then
      update public.tracker_members set user_id = auth.uid() where id = mid and user_id is null;
    else
      nm := base;
      while exists (select 1 from public.tracker_members where lower(name) = lower(nm)) loop
        n := n + 1; nm := base || ' (' || n || ')';
      end loop;
      insert into public.tracker_members (name, pin_hash, user_id)
        values (nm, crypt(encode(gen_random_bytes(12), 'hex'), gen_salt('bf')), auth.uid()) returning id into mid;
    end if;
  end if;
  return jsonb_build_object('id', mid, 'state', public.tt_state_of(mid));
end $$;
revoke all on function public.tt_me() from public, anon;
grant execute on function public.tt_me() to authenticated;

notify pgrst, 'reload schema';
