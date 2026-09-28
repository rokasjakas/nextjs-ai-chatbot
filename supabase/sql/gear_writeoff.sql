-- ============================================================
-- „Įranga“ → Nurašyti su patvirtinimu
--  * Paspaudus „Nurašyti“ galima siųsti prašymą patvirtinti. Prašymą gauna
--    visi Admin+ nariai (role 'admin', level 'plus' arba 'super').
--    Kol vienas iš jų nepatvirtina, daiktas NEnurašomas (status lieka
--    'open', sugadintas / dingęs daiktas lieka išimtas iš sandėlio kaip buvo).
--  * Patvirtinti ar atmesti gali tik Admin+ narys ir ne tas, kuris prašė
--    (tikrina serveris); kol laukiama patvirtinimo, statuso pakeisti negalima.
--  * wo_approver – kas patvirtino / atmetė.
-- Paleisti po gear.sql ir invoices.sql (public.is_plus()).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.gear_issues
  add column if not exists wo_status          text check (wo_status in ('pending','approved','rejected')),
  add column if not exists wo_approver        uuid references auth.users(id) on delete set null,
  add column if not exists wo_requested_by    uuid,
  add column if not exists wo_requested_name  text,
  add column if not exists wo_requested_at    timestamptz,
  add column if not exists wo_note            text,
  add column if not exists wo_decided_at      timestamptz,
  add column if not exists wo_decision_note   text;
drop index if exists public.gear_issues_wo;
create index if not exists gear_issues_wo_pending on public.gear_issues (wo_status) where wo_status = 'pending';

-- Admin+ mato nurašymo prašymus net jei nemato „Sandėlio“
drop policy if exists "view gear issues" on public.gear_issues;
create policy "view gear issues" on public.gear_issues for select to authenticated
  using (public.can_view('inventory') or created_by = auth.uid() or assignee = auth.uid() or auth.uid() = any(members)
         or (wo_status is not null and public.is_plus()));

drop function if exists public.gear_wo_approver();

create or replace function public.gear_me_name() returns text
  language sql stable security definer set search_path = public as $$
  select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid()
$$;

-- nurašymo laukai keičiami tik per funkcijas žemiau
create or replace function public.gear_issues_wo_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or coalesce(current_setting('gear.wo', true), '') = '1' then return new; end if;
  if tg_op = 'INSERT' then
    new.wo_status := null; new.wo_approver := null; new.wo_requested_by := null; new.wo_requested_name := null;
    new.wo_requested_at := null; new.wo_note := null; new.wo_decided_at := null; new.wo_decision_note := null;
    return new;
  end if;
  new.wo_status := old.wo_status; new.wo_approver := old.wo_approver; new.wo_requested_by := old.wo_requested_by;
  new.wo_requested_name := old.wo_requested_name; new.wo_requested_at := old.wo_requested_at; new.wo_note := old.wo_note;
  new.wo_decided_at := old.wo_decided_at; new.wo_decision_note := old.wo_decision_note;
  if old.wo_status = 'pending' and new.status is distinct from old.status then
    raise exception 'Laukiama nurašymo patvirtinimo – statuso keisti negalima, kol prašymas neišspręstas.';
  end if;
  return new;
end $$;
drop trigger if exists gear_issues_wo_guard on public.gear_issues;
create trigger gear_issues_wo_guard before insert or update on public.gear_issues
  for each row execute function public.gear_issues_wo_guard();

-- prašymas nurašyti (tas, kas tvarko „Sandėlį“)
create or replace function public.gear_wo_request(gid uuid, note text default null) returns public.gear_issues
  language plpgsql security definer set search_path = public as $$
declare g public.gear_issues;
begin
  if not public.can_edit('inventory') then raise exception 'Nurašyti gali tik tas, kas tvarko sandėlį.'; end if;
  if not exists (select 1 from public.profiles where role = 'admin' and level in ('plus','super') and id <> auth.uid()) then
    raise exception 'Nėra Admin+ nario, kuris galėtų patvirtinti.';
  end if;
  select * into g from public.gear_issues where id = gid for update;
  if not found then raise exception 'Įrašas nerastas'; end if;
  if g.status <> 'open' then raise exception 'Įrašas jau išspręstas.'; end if;
  if g.wo_status = 'pending' then raise exception 'Prašymas jau išsiųstas.'; end if;
  perform set_config('gear.wo', '1', true);
  update public.gear_issues set wo_status = 'pending', wo_approver = null, wo_requested_by = auth.uid(),
    wo_requested_name = public.gear_me_name(), wo_requested_at = now(), wo_note = nullif(trim(note), ''),
    wo_decided_at = null, wo_decision_note = null
   where id = gid returning * into g;
  perform set_config('gear.wo', '', true);
  return g;
end $$;

-- patvirtinti / atmesti (Admin+, ne tas, kuris prašė)
create or replace function public.gear_wo_decide(gid uuid, approve boolean, note text default null) returns public.gear_issues
  language plpgsql security definer set search_path = public as $$
declare g public.gear_issues;
begin
  select * into g from public.gear_issues where id = gid for update;
  if not found then raise exception 'Įrašas nerastas'; end if;
  if g.wo_status is distinct from 'pending' then raise exception 'Šis prašymas jau išspręstas.'; end if;
  if not public.is_plus() then raise exception 'Patvirtinti gali tik Admin+ narys.'; end if;
  if g.wo_requested_by = auth.uid() then raise exception 'Savo prašymo patvirtinti negalima – patvirtina kitas Admin+ narys.'; end if;
  perform set_config('gear.wo', '1', true);
  if approve then
    update public.gear_issues set wo_status = 'approved', wo_approver = auth.uid(), wo_decided_at = now(), wo_decision_note = nullif(trim(note), ''),
      status = 'written_off', resolved_at = now(), resolved_by_name = public.gear_me_name(),
      resolution = nullif(concat_ws(' · ', nullif(trim(g.wo_note), ''), nullif(trim(note), '')), '')
     where id = gid returning * into g;
  else
    update public.gear_issues set wo_status = 'rejected', wo_approver = auth.uid(), wo_decided_at = now(), wo_decision_note = nullif(trim(note), '')
     where id = gid returning * into g;
  end if;
  perform set_config('gear.wo', '', true);
  return g;
end $$;

-- atšaukti savo prašymą
create or replace function public.gear_wo_cancel(gid uuid) returns public.gear_issues
  language plpgsql security definer set search_path = public as $$
declare g public.gear_issues;
begin
  select * into g from public.gear_issues where id = gid for update;
  if not found then raise exception 'Įrašas nerastas'; end if;
  if g.wo_status is distinct from 'pending' then raise exception 'Prašymas jau išspręstas.'; end if;
  if g.wo_requested_by is distinct from auth.uid() and not public.can_edit('inventory') then raise exception 'Atšaukti gali prašymą išsiuntęs narys.'; end if;
  perform set_config('gear.wo', '1', true);
  update public.gear_issues set wo_status = null, wo_approver = null, wo_requested_by = null, wo_requested_name = null,
    wo_requested_at = null, wo_note = null, wo_decided_at = null, wo_decision_note = null
   where id = gid returning * into g;
  perform set_config('gear.wo', '', true);
  return g;
end $$;

revoke all on function public.gear_wo_request(uuid, text) from public, anon;
revoke all on function public.gear_wo_decide(uuid, boolean, text) from public, anon;
revoke all on function public.gear_wo_cancel(uuid) from public, anon;
revoke all on function public.gear_me_name() from public, anon;
grant execute on function public.gear_wo_request(uuid, text) to authenticated;
grant execute on function public.gear_wo_decide(uuid, boolean, text) to authenticated;
grant execute on function public.gear_wo_cancel(uuid) to authenticated;
grant execute on function public.gear_me_name() to authenticated;
