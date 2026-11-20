-- ============================================================
-- Transporto nuoma, 3 dalis (paleisti po rent_vehicles2.sql):
-- nuomojamo transporto nuotraukos ir dokumentai (nuomos sutartys, aktai…)
--  * kiekvienas įkėlimas – įrašas transporto istorijoje: data, pastaba, failai
--  * failai saugykloje 'fleet-files' (ta pati kaip tvarkymų),
--    kelias rent/<transporto id>/<įrašo id>/<failas>
-- Mato visi, kas mato „Transportą“ (ar Ataskaitas); įkelti ir trinti – kas redaguoja „Transportą“
-- (savo įkeltą įrašą ištrinti gali ir pats įkėlęs).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.rent_vehicle_docs (
  id               uuid primary key default gen_random_uuid(),
  rent_vehicle_id  uuid not null references public.rent_vehicles(id) on delete cascade,
  rent_date        date not null default current_date,
  note             text not null default '',
  files            jsonb not null default '[]'::jsonb,
  created_by       uuid not null default auth.uid(),
  created_by_name  text,
  created_at       timestamptz not null default now()
);
create index if not exists rent_vehicle_docs_vehicle on public.rent_vehicle_docs (rent_vehicle_id, rent_date desc);

alter table public.rent_vehicle_docs enable row level security;
drop policy if exists "rent docs view" on public.rent_vehicle_docs;
create policy "rent docs view" on public.rent_vehicle_docs for select to authenticated using (public.can_view('fleet') or public.can_view('stats'));
drop policy if exists "rent docs add" on public.rent_vehicle_docs;
create policy "rent docs add" on public.rent_vehicle_docs for insert to authenticated with check (public.can_edit('fleet') and created_by = auth.uid());
drop policy if exists "rent docs change" on public.rent_vehicle_docs;
create policy "rent docs change" on public.rent_vehicle_docs for update to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
drop policy if exists "rent docs delete" on public.rent_vehicle_docs;
create policy "rent docs delete" on public.rent_vehicle_docs for delete to authenticated using (public.can_edit('fleet') or created_by = auth.uid());
revoke all on public.rent_vehicle_docs from anon;
grant select, insert, update, delete on public.rent_vehicle_docs to authenticated;

-- the storage (the same as vehicle_logs.sql, in case that one was not run)
insert into storage.buckets (id, name, public) values ('fleet-files', 'fleet-files', false) on conflict (id) do nothing;
drop policy if exists "fleet files view" on storage.objects;
create policy "fleet files view" on storage.objects for select to authenticated
  using (bucket_id = 'fleet-files' and (public.can_view('fleet') or public.can_view('stats')));
drop policy if exists "fleet files add" on storage.objects;
create policy "fleet files add" on storage.objects for insert to authenticated
  with check (bucket_id = 'fleet-files' and public.can_view('fleet'));
drop policy if exists "fleet files delete" on storage.objects;
create policy "fleet files delete" on storage.objects for delete to authenticated
  using (bucket_id = 'fleet-files' and (public.can_edit('fleet') or owner = auth.uid()));

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';
