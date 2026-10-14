-- ============================================================
-- Transportas: automobilį pašalinti iš parko galima tik su Admin+ patvirtinimu
--  * kas redaguoja „Transportą“, siunčia prašymą (su priežastimi)
--  * patvirtina ar atmeta kitas Admin+ narys (ne tas, kuris prašė)
--  * serveris neleidžia išsaugoti parko be automobilio, kurio pašalinimas
--    nepatvirtintas (net jei kas nors bandytų apeiti programėlę)
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.vehicle_removals (
  id              uuid primary key default gen_random_uuid(),
  vehicle_id      text not null,
  vehicle_name    text not null default '',
  plate           text,
  reason          text not null default '',
  status          text not null default 'pending' check (status in ('pending','approved','rejected','cancelled','done')),
  requested_by    uuid not null default auth.uid(),
  requested_name  text,
  requested_at    timestamptz not null default now(),
  decided_by      uuid,
  decided_name    text,
  decided_at      timestamptz,
  decision_note   text,
  task_id         uuid
);
create index if not exists vehicle_removals_vehicle on public.vehicle_removals (vehicle_id, status);
-- one open request per vehicle
create unique index if not exists vehicle_removals_open on public.vehicle_removals (vehicle_id) where status in ('pending','approved');

alter table public.vehicle_removals enable row level security;
drop policy if exists "vehicle removals view" on public.vehicle_removals;
create policy "vehicle removals view" on public.vehicle_removals for select to authenticated using (public.can_view('fleet'));
-- changes only through the functions below
revoke all on public.vehicle_removals from anon, authenticated;
grant select on public.vehicle_removals to authenticated;

create or replace function public.vehicle_rm_name() returns text language sql stable security definer set search_path = public as $$
  select coalesce(nullif(trim(coalesce(first_name, '') || ' ' || coalesce(last_name, '')), ''), nickname, split_part(email, '@', 1), 'Narys')
    from public.profiles where id = auth.uid()
$$;

-- the request (anyone who edits „Transportas“)
create or replace function public.vehicle_rm_request(vid text, vname text, vplate text, note text, tid uuid default null) returns public.vehicle_removals
  language plpgsql security definer set search_path = public as $$
declare r public.vehicle_removals;
begin
  if not public.can_edit('fleet') then raise exception 'Nėra teisės redaguoti transporto'; end if;
  if coalesce(trim(note), '') = '' then raise exception 'Parašyk priežastį'; end if;
  if exists (select 1 from public.vehicle_removals where vehicle_id = vid and status in ('pending','approved')) then
    raise exception 'Šiam automobiliui prašymas jau išsiųstas';
  end if;
  insert into public.vehicle_removals (vehicle_id, vehicle_name, plate, reason, requested_name, task_id)
    values (vid, left(coalesce(vname, ''), 200), left(vplate, 40), left(trim(note), 1000), public.vehicle_rm_name(), tid)
    returning * into r;
  return r;
end $$;

-- Admin+ decides – never on one's own request
create or replace function public.vehicle_rm_decide(rid uuid, approve boolean, note text default null) returns public.vehicle_removals
  language plpgsql security definer set search_path = public as $$
declare r public.vehicle_removals;
begin
  if not public.is_plus() then raise exception 'Patvirtinti gali tik Admin+'; end if;
  select * into r from public.vehicle_removals where id = rid for update;
  if r.id is null or r.status <> 'pending' then raise exception 'Prašymas jau išspręstas'; end if;
  if r.requested_by = auth.uid() then raise exception 'Savo prašymo patvirtinti negalima – tai daro kitas Admin+ narys'; end if;
  update public.vehicle_removals set status = case when approve then 'approved' else 'rejected' end,
    decided_by = auth.uid(), decided_name = public.vehicle_rm_name(), decided_at = now(), decision_note = nullif(trim(note), '')
    where id = rid returning * into r;
  return r;
end $$;

-- the one who asked (or Admin+) takes the request back
create or replace function public.vehicle_rm_cancel(rid uuid) returns public.vehicle_removals
  language plpgsql security definer set search_path = public as $$
declare r public.vehicle_removals;
begin
  select * into r from public.vehicle_removals where id = rid for update;
  if r.id is null or r.status not in ('pending','approved') then raise exception 'Prašymas jau išspręstas'; end if;
  if r.requested_by <> auth.uid() and not public.is_plus() then raise exception 'Atšaukti gali tik prašęs arba Admin+'; end if;
  update public.vehicle_removals set status = 'cancelled', decided_by = auth.uid(), decided_name = public.vehicle_rm_name(), decided_at = now()
    where id = rid returning * into r;
  return r;
end $$;

revoke all on function public.vehicle_rm_request(text, text, text, text, uuid) from public, anon;
revoke all on function public.vehicle_rm_decide(uuid, boolean, text) from public, anon;
revoke all on function public.vehicle_rm_cancel(uuid) from public, anon;
grant execute on function public.vehicle_rm_request(text, text, text, text, uuid) to authenticated;
grant execute on function public.vehicle_rm_decide(uuid, boolean, text) to authenticated;
grant execute on function public.vehicle_rm_cancel(uuid) to authenticated;

-- the guard: the fleet (app_state 'vehicles') may lose a vehicle only with an approved request
create or replace function public.vehicles_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
declare gone text[]; v text;
begin
  if auth.uid() is null then return coalesce(new, old); end if;          -- server jobs, SQL editor
  if tg_op = 'DELETE' then
    if old.key = 'vehicles' and jsonb_array_length(coalesce(old.data, '[]'::jsonb)) > 0 then
      raise exception 'Automobilį pašalinti galima tik su Admin+ patvirtinimu';
    end if;
    return old;
  end if;
  if new.key <> 'vehicles' or tg_op <> 'UPDATE' then return new; end if;
  gone := array(
    select o->>'id' from jsonb_array_elements(case when jsonb_typeof(old.data) = 'array' then old.data else '[]'::jsonb end) o
     where o->>'id' is not null
       and not exists (select 1 from jsonb_array_elements(case when jsonb_typeof(new.data) = 'array' then new.data else '[]'::jsonb end) n where n->>'id' = o->>'id'));
  foreach v in array gone loop
    if not exists (select 1 from public.vehicle_removals where vehicle_id = v and status = 'approved') then
      raise exception 'Automobilį pašalinti galima tik su Admin+ patvirtinimu';
    end if;
    update public.vehicle_removals set status = 'done' where vehicle_id = v and status = 'approved';
  end loop;
  return new;
end $$;
drop trigger if exists vehicles_guard on public.app_state;
create trigger vehicles_guard before update or delete on public.app_state
  for each row execute function public.vehicles_guard();

-- Supabase: read the list of tables and functions again
notify pgrst, 'reload schema';
