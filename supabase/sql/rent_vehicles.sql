-- ============================================================
-- Transportas → „Transporto nuoma“: nuomojamas transportas (mikroautobusai ir fūros)
--  * įmonė, transportas, valst. nr., išmatavimai, keliamoji galia,
--    paros nuomos kaina, kontaktai, pastabos
--  * „Kaip rašoma renginiuose“ – vardai / žodžiai (pvz. Alius), pagal kuriuos
--    Ataskaitos → Transporto nuoma pridės kainą ir kontaktus
-- Mato visi, kas mato „Transportą“; keisti – kas jį redaguoja.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.rent_vehicles (
  id            uuid primary key default gen_random_uuid(),
  kind          text not null default 'van' check (kind in ('van','truck')),
  company       text not null default '',
  name          text not null default '',
  plate         text,
  aliases       text not null default '',
  length_cm     numeric(8,1),
  width_cm      numeric(8,1),
  height_cm     numeric(8,1),
  max_kg        numeric(10,1),
  price_day     numeric(10,2),
  price_note    text not null default '',
  contact_name  text not null default '',
  phone         text not null default '',
  email         text not null default '',
  note          text not null default '',
  active        boolean not null default true,
  created_by    uuid default auth.uid(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

alter table public.rent_vehicles enable row level security;
drop policy if exists "rent vehicles view" on public.rent_vehicles;
create policy "rent vehicles view" on public.rent_vehicles for select to authenticated using (public.can_view('fleet') or public.can_view('stats'));
drop policy if exists "rent vehicles edit" on public.rent_vehicles;
create policy "rent vehicles edit" on public.rent_vehicles for all to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
revoke all on public.rent_vehicles from anon;
grant select, insert, update, delete on public.rent_vehicles to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';
