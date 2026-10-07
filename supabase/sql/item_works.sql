-- ============================================================
-- Sandėlis → „Atlikti darbai“: valymas, profilaktinė patikra, remontas…
--  * įrašas: kada, koks darbas, su kuriais daiktais (ar visa grupe),
--    kas darė, pastaba, nuotraukos
--  * nuotraukos saugykloje 'equipment-photos', kelias works/<įrašo id>/<failas>
-- Mato visi, kas mato „Sandėlį“; registruoti – kas redaguoja „Sandėlį“
-- (savo įrašą pataisyti / ištrinti gali ir pats įrašęs).
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.item_works (
  id               uuid primary key default gen_random_uuid(),
  work_date        date not null default current_date,
  kind             text not null default '',
  item_ids         text[] not null default '{}',
  item_names       text[] not null default '{}',
  scope            text not null default '',      -- a whole group / subgroup, e.g. „Garsas › Kolonėlės“
  done_by          text[] not null default '{}',  -- who did it (names)
  note             text not null default '',
  files            jsonb not null default '[]'::jsonb,
  created_by       uuid not null default auth.uid(),
  created_by_name  text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);
create index if not exists item_works_date on public.item_works (work_date desc);

alter table public.item_works enable row level security;
drop policy if exists "item works view" on public.item_works;
create policy "item works view" on public.item_works for select to authenticated using (public.can_view('inventory'));
drop policy if exists "item works add" on public.item_works;
create policy "item works add" on public.item_works for insert to authenticated with check (public.can_edit('inventory') and created_by = auth.uid());
drop policy if exists "item works change" on public.item_works;
create policy "item works change" on public.item_works for update to authenticated using (public.can_edit('inventory') or created_by = auth.uid()) with check (public.can_edit('inventory') or created_by = auth.uid());
drop policy if exists "item works delete" on public.item_works;
create policy "item works delete" on public.item_works for delete to authenticated using (public.can_edit('inventory') or created_by = auth.uid());
revoke all on public.item_works from anon;
grant select, insert, update, delete on public.item_works to authenticated;

-- photos: equipment-photos/works/… – seen by who sees Sandėlis, added by who edits it
create or replace function public.equipment_photo_access(obj_name text, edit boolean) returns boolean
  language sql stable security definer set search_path = public as $$
  select case (storage.foldername(obj_name))[1]
    when 'rentals'   then case when edit then public.can_edit('rentals')   else public.can_view('rentals')   end
    when 'handovers' then case when edit then public.can_edit('handovers') else public.can_view('handovers') end
    when 'gear'      then public.can_view('inventory')
    when 'works'     then case when edit then public.can_edit('inventory') else public.can_view('inventory') end
    else false end
$$;
grant execute on function public.equipment_photo_access(text, boolean) to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';
