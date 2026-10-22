-- ============================================================
-- Profilis → Prašymai: laisvos dienos ir atostogos
--  * kind 'dayoff'  – konkrečios dienos (days), date_from/date_to = pirma/paskutinė
--  * kind 'vacation' – laikotarpis date_from … date_to
--  * Prašymą mato jį pateikęs narys, „office“ nariai ir Admin+;
--    patvirtinti / atmesti gali tik Admin+ (ne savo prašymo).
--  * Patvirtintos dienos (be priežasčių) visiems prisijungusiems grąžina
--    leave_busy() – pagal jas renginiuose neleidžiama įrašyti nario.
-- Paleisti po invoices.sql (public.is_plus()). Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.leave_requests (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid not null default auth.uid() references auth.users(id) on delete cascade,
  user_name        text,
  kind             text not null check (kind in ('dayoff','vacation')),
  days             date[] not null default '{}',
  date_from        date not null,
  date_to          date not null,
  reason           text not null default '',
  status           text not null default 'pending' check (status in ('pending','approved','rejected','cancelled')),
  decided_by       uuid references auth.users(id) on delete set null,
  decided_by_name  text,
  decided_at       timestamptz,
  decision_note    text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  check (date_to >= date_from),
  check (date_to - date_from <= 366),
  check (kind <> 'dayoff' or cardinality(days) between 1 and 60)
);
create index if not exists leave_requests_user on public.leave_requests (user_id, created_at desc);
create index if not exists leave_requests_open on public.leave_requests (status, date_to);

-- Admin+ (tas pats kaip invoices.sql)
create or replace function public.is_plus() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'admin' and level in ('plus','super') from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.is_plus() to authenticated;

create or replace function public.leave_can_see_all() returns boolean
  language sql stable security definer set search_path = public as $$
  select public.is_plus() or coalesce((select role = 'office' from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.leave_can_see_all() to authenticated;

alter table public.leave_requests enable row level security;
drop policy if exists "view leave" on public.leave_requests;
create policy "view leave" on public.leave_requests for select to authenticated
  using (user_id = auth.uid() or public.leave_can_see_all());
drop policy if exists "ask leave" on public.leave_requests;
create policy "ask leave" on public.leave_requests for insert to authenticated
  with check (user_id = auth.uid() and public.is_approved());
-- keisti galima tik per funkcijas žemiau
drop policy if exists "change leave" on public.leave_requests;
grant select, insert on public.leave_requests to authenticated;
revoke update, delete on public.leave_requests from authenticated;

-- naujas prašymas: kas, kada, būsena 'pending' ir dienos – nustato serveris
create or replace function public.leave_requests_stamp() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or coalesce(current_setting('leave.rpc', true), '') = '1' then return new; end if;
  new.user_id := auth.uid();
  new.user_name := (select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid());
  new.status := 'pending'; new.decided_by := null; new.decided_by_name := null; new.decided_at := null; new.decision_note := null;
  new.created_at := now(); new.updated_at := now();
  new.reason := trim(coalesce(new.reason, ''));
  if new.reason = '' then raise exception 'Parašyk, kodėl prašai.'; end if;
  if new.kind = 'dayoff' then
    new.days := (select array_agg(distinct d order by d) from unnest(new.days) d);
    if new.days is null then raise exception 'Pasirink bent vieną dieną.'; end if;
    new.date_from := new.days[1]; new.date_to := new.days[array_length(new.days, 1)];
  else
    new.days := '{}';
  end if;
  if new.date_to < current_date then raise exception 'Negalima prašyti praėjusių dienų.'; end if;
  return new;
end $$;
drop trigger if exists leave_requests_stamp on public.leave_requests;
create trigger leave_requests_stamp before insert on public.leave_requests
  for each row execute function public.leave_requests_stamp();

create or replace function public.leave_me_name() returns text
  language sql stable security definer set search_path = public as $$
  select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid()
$$;

-- patvirtinti / atmesti: tik Admin+, ne savo prašymo
create or replace function public.leave_decide(rid uuid, approve boolean, note text default null) returns public.leave_requests
  language plpgsql security definer set search_path = public as $$
declare r public.leave_requests;
begin
  if not public.is_plus() then raise exception 'Patvirtinti gali tik Admin+ narys.'; end if;
  select * into r from public.leave_requests where id = rid for update;
  if not found then raise exception 'Prašymas nerastas'; end if;
  if r.status <> 'pending' then raise exception 'Šis prašymas jau išspręstas.'; end if;
  if r.user_id = auth.uid() then raise exception 'Savo prašymo patvirtinti negalima – patvirtina kitas Admin+ narys.'; end if;
  perform set_config('leave.rpc', '1', true);
  update public.leave_requests set status = case when approve then 'approved' else 'rejected' end,
    decided_by = auth.uid(), decided_by_name = public.leave_me_name(), decided_at = now(),
    decision_note = nullif(trim(note), ''), updated_at = now()
   where id = rid returning * into r;
  perform set_config('leave.rpc', '', true);
  return r;
end $$;

-- atšaukti savo prašymą (laukiantį arba patvirtintą, kol jis dar nesibaigė)
create or replace function public.leave_cancel(rid uuid) returns public.leave_requests
  language plpgsql security definer set search_path = public as $$
declare r public.leave_requests;
begin
  select * into r from public.leave_requests where id = rid for update;
  if not found then raise exception 'Prašymas nerastas'; end if;
  if r.user_id <> auth.uid() and not public.is_plus() then raise exception 'Atšaukti gali tik prašymą pateikęs narys.'; end if;
  if r.status not in ('pending','approved') then raise exception 'Šio prašymo atšaukti nebegalima.'; end if;
  if r.date_to < current_date then raise exception 'Laikotarpis jau praėjęs.'; end if;
  perform set_config('leave.rpc', '1', true);
  update public.leave_requests set status = 'cancelled', updated_at = now() where id = rid returning * into r;
  perform set_config('leave.rpc', '', true);
  return r;
end $$;

-- patvirtintos laisvos dienos / atostogos (be priežasčių) – renginių tikrinimui
create or replace function public.leave_busy() returns table (user_id uuid, kind text, days date[], date_from date, date_to date)
  language sql stable security definer set search_path = public as $$
  select l.user_id, l.kind, l.days, l.date_from, l.date_to
    from public.leave_requests l
   where l.status = 'approved' and l.date_to >= current_date - 400 and public.is_approved()
$$;

revoke all on function public.leave_decide(uuid, boolean, text) from public, anon;
revoke all on function public.leave_cancel(uuid) from public, anon;
revoke all on function public.leave_busy() from public, anon;
revoke all on function public.leave_me_name() from public, anon;
grant execute on function public.leave_decide(uuid, boolean, text) to authenticated;
grant execute on function public.leave_cancel(uuid) to authenticated;
grant execute on function public.leave_busy() to authenticated;
grant execute on function public.leave_me_name() to authenticated;

-- pokyčiai iš karto (Realtime)
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'leave_requests') then
    execute 'alter publication supabase_realtime add table public.leave_requests';
  end if;
end $$;
