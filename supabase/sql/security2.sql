-- ============================================================
-- Saugumo sustiprinimai (2) – pagal security.sql patikrinimo rezultatą
--  1. Bendrinami projektai (?share=…): anksčiau neprisijungęs galėjo gauti
--     VISŲ bendrinamų projektų sąrašą. Dabar – tik vieną, žinant jo nuorodą
--     (funkcija guest_project). Programa v110+ naudoja ją.
--  2. Senos, programos nebenaudojamos lentelės (custom_items,
--     inventory_overrides, packing_rules, sessions_log, vehicles):
--     taisyklė „org members full access“ pakeičiama „tik administratoriai“.
--     Duomenys lieka.
--  3. Sena funkcija guest_update_qty: nustatomas search_path, neprisijungusiems
--     kviesti draudžiama.
-- Pabaigoje – tas pats patikrinimas. Tuščias rezultatas = gerai.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- 1. bendrinamas projektas tik pagal nuorodą
create or replace function public.guest_project(tok text) returns jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'project', to_jsonb(p),
    'items', coalesce((select jsonb_agg(to_jsonb(i) order by i.created_at) from public.project_items i where i.project_id = p.id), '[]'::jsonb))
  from public.projects p
  where p.share_enabled = true and coalesce(tok, '') <> '' and p.share_token::text = tok
  limit 1
$$;
revoke all on function public.guest_project(text) from public;
grant execute on function public.guest_project(text) to anon, authenticated;
drop policy if exists "public shared projects" on public.projects;
drop policy if exists "public shared project items" on public.project_items;

-- 2. senos lentelės – tik administratoriams
do $$
declare t text;
begin
  foreach t in array array['custom_items','inventory_overrides','packing_rules','sessions_log','vehicles'] loop
    if to_regclass('public.' || t) is not null then
      execute format('alter table public.%I enable row level security', t);
      execute format('drop policy if exists %I on public.%I', 'org members full access', t);
      execute format('drop policy if exists %I on public.%I', 'admins only (old table)', t);
      execute format('create policy %I on public.%I for all to authenticated using (public.is_admin()) with check (public.is_admin())', 'admins only (old table)', t);
      execute format('revoke all on public.%I from anon', t);
    end if;
  end loop;
end $$;

-- 3. sena funkcija guest_update_qty
do $$
declare f record;
begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'public' and p.proname = 'guest_update_qty' loop
    execute format('alter function %s set search_path = public', f.sig);
    execute format('revoke execute on function %s from public, anon', f.sig);
  end loop;
end $$;

-- ============================================================
-- PATIKRINIMAS (tik skaito)
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
