-- ============================================================
-- „Įranga“: pažeista / sugadinta ir dingusi įranga
--  * kind 'damage': state 'usable' (pažeista, bet naudojama – kiekis
--    nesikeičia) arba 'broken' (negalima naudoti – išimama iš sandėlio,
--    kol status nepasikeičia į 'fixed');
--    assignee – kas atsakingas už taisymą (jam sukuriama užduotis)
--  * kind 'lost': kas dingo, kada pastebėta, kur galimai; members – kas
--    pažymėti (gauna pranešimą); išimama iš sandėlio, kol 'found'
--  * status: open | fixed | found | written_off (nurašyta – lieka išimta)
--  * mato ir praneša tie, kas mato „Sandėlį“; tvarko – kas jį redaguoja,
--    taip pat pranešęs, atsakingas ir pažymėti nariai
--  * nuotraukos: 'equipment-photos' saugykla, gear/<id>/…
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.gear_issues (
  id               uuid primary key default gen_random_uuid(),
  kind             text not null check (kind in ('damage','lost')),
  item_id          text,
  item_name        text not null default '',
  qty              integer not null default 1 check (qty > 0 and qty < 100000),
  state            text not null default 'usable' check (state in ('usable','broken','lost')),
  status           text not null default 'open' check (status in ('open','fixed','found','written_off')),
  description      text not null default '',
  place            text,
  noticed_at       date,
  event_name       text,
  photos           jsonb not null default '[]'::jsonb,
  assignee         uuid references auth.users(id) on delete set null,
  members          uuid[] not null default '{}',
  task_id          uuid,
  created_by       uuid not null default auth.uid(),
  created_by_name  text,
  created_at       timestamptz not null default now(),
  resolved_at      timestamptz,
  resolved_by_name text,
  resolution       text,
  updated_at       timestamptz not null default now()
);
create index if not exists gear_issues_open on public.gear_issues (status, item_id);

alter table public.gear_issues enable row level security;
drop policy if exists "view gear issues" on public.gear_issues;
create policy "view gear issues" on public.gear_issues for select to authenticated
  using (public.can_view('inventory') or created_by = auth.uid() or assignee = auth.uid() or auth.uid() = any(members));
drop policy if exists "report gear issues" on public.gear_issues;
create policy "report gear issues" on public.gear_issues for insert to authenticated
  with check (public.can_view('inventory') and created_by = auth.uid());
drop policy if exists "change gear issues" on public.gear_issues;
create policy "change gear issues" on public.gear_issues for update to authenticated
  using (public.can_edit('inventory') or created_by = auth.uid() or assignee = auth.uid() or auth.uid() = any(members))
  with check (public.can_edit('inventory') or created_by = auth.uid() or assignee = auth.uid() or auth.uid() = any(members));
drop policy if exists "delete gear issues" on public.gear_issues;
create policy "delete gear issues" on public.gear_issues for delete to authenticated
  using (public.can_edit('inventory'));
grant select, insert, update, delete on public.gear_issues to authenticated;

-- pranešęs žmogus ir laikas – nustato serveris
create or replace function public.gear_issues_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  if tg_op = 'INSERT' then
    new.created_by := auth.uid();
    new.created_at := now();
    new.created_by_name := coalesce((select nullif(trim(concat_ws(' ', p.first_name, p.last_name)), '') from public.profiles p where p.id = auth.uid()), new.created_by_name);
  else
    new.created_by := old.created_by; new.created_at := old.created_at; new.created_by_name := old.created_by_name;
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists gear_issues_stamp on public.gear_issues;
create trigger gear_issues_stamp before insert or update on public.gear_issues
  for each row execute function public.gear_issues_stamp();

-- pokyčiai iš karto visiems (Realtime)
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'gear_issues') then
    execute 'alter publication supabase_realtime add table public.gear_issues';
  end if;
end $$;

-- nuotraukos: ta pati 'equipment-photos' saugykla, aplankas gear/
create or replace function public.equipment_photo_access(obj_name text, edit boolean) returns boolean
  language sql stable security definer set search_path = public as $$
  select case (storage.foldername(obj_name))[1]
    when 'rentals'   then case when edit then public.can_edit('rentals')   else public.can_view('rentals')   end
    when 'handovers' then case when edit then public.can_edit('handovers') else public.can_view('handovers') end
    when 'gear'      then public.can_view('inventory')
    else false end
$$;
grant execute on function public.equipment_photo_access(text, boolean) to authenticated;
