-- ============================================================
-- Saugumo sustiprinimai (2026-09)
--  1. Kas įrašė – nustato serveris, ne naršyklė: žaidimų rezultatų
--     vardas, inventorizacijos istorijos autorius ir „kas keitė“ laukai
--     nebegali būti suklastoti (anksčiau juos siuntė programa).
--  2. Žaidimų rezultatai: ne dažniau kaip 30 per minutę vienam žmogui.
--  3. Pabaigoje – PATIKRINIMAS: parodo lenteles be RLS, taisykles, kurios
--     leidžia rašyti bet kam, SECURITY DEFINER funkcijas be search_path ir
--     viešas saugyklas. Tuščias rezultatas = gerai.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- vardas iš profilio (ne iš naršyklės)
create or replace function public.me_display_name() returns text
  language sql stable security definer set search_path = public as $$
  select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.full_name, split_part(p.email, '@', 1), 'Narys')
  from public.profiles p where p.id = auth.uid()
$$;
grant execute on function public.me_display_name() to authenticated;

-- 1a. game_scores: savo vardu ir be šlamšto
create or replace function public.game_scores_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;               -- SQL Editor / service role
  new.user_id := auth.uid();
  new.name := coalesce(public.me_display_name(), 'Narys');
  new.created_at := now();
  if (select count(*) from public.game_scores where user_id = auth.uid() and created_at > now() - interval '1 minute') >= 30 then
    raise exception 'Per daug rezultatų per minutę.';
  end if;
  return new;
end $$;
drop trigger if exists game_scores_stamp on public.game_scores;
create trigger game_scores_stamp before insert on public.game_scores
  for each row execute function public.game_scores_stamp();

-- 1b. stk_log: autorius – prisijungęs žmogus, laikas – serverio
create or replace function public.stk_log_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  new.by_id := auth.uid();
  new.by_name := public.me_display_name();
  new.at := now();
  return new;
end $$;
drop trigger if exists stk_log_stamp on public.stk_log;
create trigger stk_log_stamp before insert on public.stk_log
  for each row execute function public.stk_log_stamp();

-- 1c. „kas keitė“ laukai
create or replace function public.stamp_updated_by() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  new.updated_by := public.me_display_name();
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists stk_items_stamp on public.stk_items;
create trigger stk_items_stamp before insert or update on public.stk_items
  for each row execute function public.stamp_updated_by();
drop trigger if exists stk_sessions_stamp on public.stk_sessions;
create trigger stk_sessions_stamp before insert or update on public.stk_sessions
  for each row execute function public.stamp_updated_by();

-- 1d. user_notes: tik savo (id visada '<savo id>:<vieta>')
create or replace function public.user_notes_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  new.user_id := auth.uid();
  new.id := auth.uid()::text || ':' || new.key;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists user_notes_stamp on public.user_notes;
create trigger user_notes_stamp before insert or update on public.user_notes
  for each row execute function public.user_notes_stamp();

-- ============================================================
-- 3. PATIKRINIMAS (tik skaito, nieko nekeičia)
-- ============================================================
select 'Lentelė be RLS' as problema, schemaname || '.' || tablename as kas
  from pg_tables where schemaname = 'public' and not rowsecurity
union all
select 'Taisyklė leidžia rašyti visiems', schemaname || '.' || tablename || ' → ' || policyname
  from pg_policies
  where schemaname = 'public' and cmd in ('INSERT','UPDATE','DELETE','ALL')
    and (coalesce(qual, '') in ('true', '') and coalesce(with_check, '') in ('true', ''))
union all
select 'Taisyklė atvira neprisijungusiems (anon)', schemaname || '.' || tablename || ' → ' || policyname
  from pg_policies where schemaname = 'public' and ('anon' = any(roles) or 'public' = any(roles))
union all
select 'SECURITY DEFINER be search_path', n.nspname || '.' || p.proname
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and p.prosecdef
    and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) c where c like 'search_path=%')
union all
select 'Vieša saugykla (failai be prisijungimo)', id from storage.buckets where public
order by 1, 2;
