-- ============================================================
-- „Inventorizacija“: skyriai (lapai) – pridėti, pervadinti, ištrinti, tvarka
--  * stk_sheets – skyrių sąrašas ir tvarka (skyrius gali būti ir tuščias – daiktai pridedami vėliau);
--    skyriai, kurie jau yra daiktuose, rodomi ir be eilutės čia
--  * stk_sheet_rename – pervadina skyrių visur vienu kartu: daiktuose, inventorizacijose, istorijoje
--  * stk_sheet_delete – ištrina skyrių su jo daiktais ir inventorizacijomis (su priežastimi – lieka istorijoje)
--  * keičia tie, kas redaguoja „Sandėlį“ (can_edit('inventory')), mato – kas jį mato
-- Reikia: stocktake.sql. Paleidžiama per „SQL paleidimas“. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.stk_sheets (
  name       text primary key,
  sort       double precision not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  updated_by text
);
alter table public.stk_sheets enable row level security;
drop policy if exists "view stk_sheets" on public.stk_sheets;
create policy "view stk_sheets" on public.stk_sheets for select to authenticated using (public.can_view('inventory'));
drop policy if exists "edit stk_sheets" on public.stk_sheets;
create policy "edit stk_sheets" on public.stk_sheets for all to authenticated
  using (public.can_edit('inventory')) with check (public.can_edit('inventory'));
grant select, insert, update, delete on public.stk_sheets to authenticated;
grant select, insert, update, delete on public.stk_sheets to service_role;

create or replace function public.stk_sheet_rename(p_from text, p_to text, p_by text default null) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare n_items int; n_sess int;
begin
  if not public.can_edit('inventory') then raise exception 'Keisti gali tik tie, kas redaguoja Sandėlį.'; end if;
  p_to := btrim(coalesce(p_to, ''));
  if p_to = '' then raise exception 'Įrašyk pavadinimą.'; end if;
  if p_to = p_from then return jsonb_build_object('ok', true); end if;
  if exists (select 1 from public.stk_items where sheet = p_to) or exists (select 1 from public.stk_sheets where name = p_to)
     or exists (select 1 from public.stk_sessions where sheet = p_to) then
    raise exception 'Skyrius „%“ jau yra.', p_to;
  end if;
  update public.stk_items set sheet = p_to, updated_at = now(), updated_by = p_by where sheet = p_from;
  get diagnostics n_items = row_count;
  update public.stk_sessions set sheet = p_to, updated_at = now(), updated_by = p_by where sheet = p_from;
  get diagnostics n_sess = row_count;
  update public.stk_sheets set name = p_to, updated_at = now(), updated_by = p_by where name = p_from;
  update public.stk_log set sheet = p_to where sheet = p_from;   -- the history follows the section
  insert into public.stk_log (by_name, sheet, name, action, from_v, to_v) values (p_by, p_to, p_to, 'sheet_rename', p_from, p_to);
  return jsonb_build_object('ok', true, 'items', n_items, 'sessions', n_sess);
end $$;
grant execute on function public.stk_sheet_rename(text, text, text) to authenticated;

create or replace function public.stk_sheet_delete(p_name text, p_reason text, p_by text default null) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare n_items int; n_sess int;
begin
  if not public.can_edit('inventory') then raise exception 'Trinti gali tik tie, kas redaguoja Sandėlį.'; end if;
  if length(btrim(coalesce(p_reason, ''))) < 3 then raise exception 'Įrašyk priežastį.'; end if;
  delete from public.stk_items where sheet = p_name;
  get diagnostics n_items = row_count;
  delete from public.stk_sessions where sheet = p_name;
  get diagnostics n_sess = row_count;
  delete from public.stk_sheets where name = p_name;
  insert into public.stk_log (by_name, sheet, name, action, from_v, to_v, reason)
    values (p_by, p_name, p_name, 'sheet_delete', n_items || ' daikt., ' || n_sess || ' inv.', '', btrim(p_reason));
  return jsonb_build_object('ok', true, 'items', n_items, 'sessions', n_sess);
end $$;
grant execute on function public.stk_sheet_delete(text, text, text) to authenticated;

notify pgrst, 'reload schema';
select 'stk_sheets' as k, count(*)::text as v from public.stk_sheets
union all select 'skyriai daiktuose', count(distinct sheet)::text from public.stk_items;
