-- ============================================================
-- Transportas: automobilių tvarkymai ir pastebėtos problemos
--  * kind 'service' – tvarkymas (data, rida, kategorija, kas atlikta,
--    servisas, kaina, sąskaitos) – registruoja tas, kas redaguoja „Transportą“
--  * kind 'problem' – pastebėta problema (data, rida, aprašymas, kaip skubu,
--    nuotraukos) – gali pranešti visi, kas mato „Transportą“;
--    status 'open' → 'fixed' (fixed_by – tvarkymas, kuriuo sutvarkyta)
--  * failai (sąskaitos PDF, nuotraukos): saugykla 'fleet-files',
--    kelias <vehicle_id>/<įrašo id>/<failas>
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.vehicle_logs (
  id               uuid primary key default gen_random_uuid(),
  vehicle_id       text not null,
  vehicle_name     text,
  kind             text not null check (kind in ('service','problem')),
  log_date         date not null default current_date,
  mileage          integer check (mileage is null or (mileage >= 0 and mileage < 10000000)),
  category         text,
  title            text not null default '',
  description      text not null default '',
  place            text,
  cost             numeric(12,2) check (cost is null or (cost >= 0 and cost < 10000000)),
  severity         text check (severity is null or severity in ('low','soon','stop')),
  status           text not null default 'open' check (status in ('open','fixed','done')),
  fixed_by         uuid,
  fixed_at         date,
  files            jsonb not null default '[]'::jsonb,
  created_by       uuid not null default auth.uid(),
  created_by_name  text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);
create index if not exists vehicle_logs_vehicle on public.vehicle_logs (vehicle_id, log_date desc);
create index if not exists vehicle_logs_date on public.vehicle_logs (log_date);

alter table public.vehicle_logs enable row level security;
drop policy if exists "fleet logs view" on public.vehicle_logs;
create policy "fleet logs view" on public.vehicle_logs for select to authenticated
  using (public.can_view('fleet'));
drop policy if exists "fleet logs add" on public.vehicle_logs;
create policy "fleet logs add" on public.vehicle_logs for insert to authenticated
  with check (public.can_view('fleet') and created_by = auth.uid() and (kind = 'problem' or public.can_edit('fleet')));
drop policy if exists "fleet logs change" on public.vehicle_logs;
create policy "fleet logs change" on public.vehicle_logs for update to authenticated
  using (public.can_edit('fleet') or created_by = auth.uid())
  with check (public.can_edit('fleet') or (created_by = auth.uid() and kind = 'problem'));
drop policy if exists "fleet logs delete" on public.vehicle_logs;
create policy "fleet logs delete" on public.vehicle_logs for delete to authenticated
  using (public.can_edit('fleet') or created_by = auth.uid());
revoke all on public.vehicle_logs from anon;
grant select, insert, update, delete on public.vehicle_logs to authenticated;

-- kas įrašė ir kada – nustato serveris
create or replace function public.vehicle_logs_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  if tg_op = 'INSERT' then
    new.created_by := auth.uid();
    new.created_at := now();
    new.created_by_name := coalesce((select nullif(trim(concat_ws(' ', p.first_name, p.last_name)), '') from public.profiles p where p.id = auth.uid()), new.created_by_name);
  else
    new.created_by := old.created_by; new.created_at := old.created_at; new.created_by_name := old.created_by_name;
    new.kind := old.kind;
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists vehicle_logs_stamp on public.vehicle_logs;
create trigger vehicle_logs_stamp before insert or update on public.vehicle_logs
  for each row execute function public.vehicle_logs_stamp();

-- pokyčiai iš karto (Realtime)
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'vehicle_logs') then
    execute 'alter publication supabase_realtime add table public.vehicle_logs';
  end if;
end $$;

-- sąskaitos ir nuotraukos
insert into storage.buckets (id, name, public) values ('fleet-files', 'fleet-files', false) on conflict (id) do nothing;
drop policy if exists "fleet files view" on storage.objects;
create policy "fleet files view" on storage.objects for select to authenticated
  using (bucket_id = 'fleet-files' and public.can_view('fleet'));
drop policy if exists "fleet files add" on storage.objects;
create policy "fleet files add" on storage.objects for insert to authenticated
  with check (bucket_id = 'fleet-files' and public.can_view('fleet'));
drop policy if exists "fleet files delete" on storage.objects;
create policy "fleet files delete" on storage.objects for delete to authenticated
  using (bucket_id = 'fleet-files' and (public.can_edit('fleet') or owner = auth.uid()));
