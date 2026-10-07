-- ============================================================
-- Sąskaitų patikra ofise (Freelance sąskaitos)
--  * Office, Projektų vadovai (ir Admin) mato gautas sąskaitas (Freelance, iš portalo,
--    iš el. pašto), gali pakeisti rūšį, parašyti siuntėjui (viskas tvarkoje / reikia korekcijų)
--    ir pažymėti „Sąskaita patikrinta“
--  * Freelance sąskaita Admin+ „Naujose“ atsiranda tik patikrinta ofise
--  * checked_by / checked_at – kas ir kada patikrino; check_msgs – žinutės siuntėjui ir patikros istorija
-- Reikia: invoices.sql, invoice_inbox.sql. Funkcijos: push-notify, files, freelance-portal.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.invoices add column if not exists checked_by uuid references auth.users(id) on delete set null;
alter table public.invoices add column if not exists checked_at timestamptz;
alter table public.invoices add column if not exists check_msgs jsonb not null default '[]'::jsonb;   -- [{at, by, who, kind:'ok'|'fix'|'note'|'checked'|'kind', text, to}]

-- kas tikrina: Office, Projektų vadovas, Admin
create or replace function public.is_inv_checker() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select role in ('office','pm','admin') from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.is_inv_checker() to authenticated;

-- kurios sąskaitos tikrinamos: Freelance ir gautos iš išorės (portalas, el. paštas)
create or replace function public.inv_checkable(k text, src text) returns boolean
  language sql immutable as $$ select k = 'freelance' or coalesce(src, '') in ('portal','email') $$;

drop policy if exists "invoices check read" on public.invoices;
create policy "invoices check read" on public.invoices
  for select to authenticated using (public.is_inv_checker() and public.inv_checkable(kind, source));

-- failai: tikrintojas mato tikrinamų sąskaitų failus
create or replace function public.inv_file_checkable(p_path text) returns boolean
  language sql stable security definer set search_path = public as $$
  select public.is_inv_checker() and exists (
    select 1 from public.invoices i
    where public.inv_checkable(i.kind, i.source) and i.files @> jsonb_build_array(jsonb_build_object('path', p_path)))
$$;
grant execute on function public.inv_file_checkable(text) to authenticated;
drop policy if exists "invoice files check view" on storage.objects;
create policy "invoice files check view" on storage.objects
  for select to authenticated using (bucket_id = 'invoice-files' and public.inv_file_checkable(name));

-- patikros veiksmai (tik per šią funkciją: tikrintojas kitų laukų keisti negali)
--   kind  – priskirti rūšį;  check – „Sąskaita patikrinta“ (tik Freelance);  uncheck – atšaukti;
--   note  – žinutė į istoriją (laiškas siuntėjui eina per push-notify)
create or replace function public.invoice_office(p_id uuid, p_action text, p_kind text default null, p_text text default null)
  returns public.invoices language plpgsql security definer set search_path = public as $$
declare v public.invoices; who text;
begin
  if not (public.is_inv_checker() or public.is_plus()) then raise exception 'Sąskaitas tikrina Office, Projektų vadovai ir Admin.'; end if;
  select * into v from public.invoices where id = p_id for update;
  if not found or not public.inv_checkable(v.kind, v.source) then raise exception 'Sąskaita nerasta.'; end if;
  if v.status not in ('new','later') and p_action <> 'note' then raise exception 'Sąskaita jau sutvarkyta (Admin+ sprendimas priimtas).'; end if;
  select coalesce(nullif(trim(coalesce(first_name,'')||' '||coalesce(last_name,'')),''), full_name, email) into who from public.profiles where id = auth.uid();
  if p_action = 'kind' then
    if p_kind not in ('freelance','service','rent','purchase','other') then raise exception 'Nežinoma rūšis.'; end if;
    update public.invoices set kind = p_kind,
      check_msgs = check_msgs || jsonb_build_array(jsonb_build_object('at', now(), 'by', auth.uid(), 'who', who, 'kind', 'kind', 'text', p_kind))
      where id = p_id returning * into v;
  elsif p_action = 'check' then
    if v.kind <> 'freelance' then raise exception 'Patikra reikalinga tik Freelance sąskaitoms.'; end if;
    update public.invoices set checked_at = now(), checked_by = auth.uid(),
      check_msgs = check_msgs || jsonb_build_array(jsonb_build_object('at', now(), 'by', auth.uid(), 'who', who, 'kind', 'checked', 'text', coalesce(p_text,'')))
      where id = p_id returning * into v;
  elsif p_action = 'uncheck' then
    update public.invoices set checked_at = null, checked_by = null,
      check_msgs = check_msgs || jsonb_build_array(jsonb_build_object('at', now(), 'by', auth.uid(), 'who', who, 'kind', 'unchecked', 'text', ''))
      where id = p_id returning * into v;
  elsif p_action = 'note' then
    update public.invoices set check_msgs = check_msgs || jsonb_build_array(jsonb_build_object('at', now(), 'by', auth.uid(), 'who', who, 'kind', 'note', 'text', left(coalesce(p_text,''), 2000)))
      where id = p_id returning * into v;
  else raise exception 'Nežinomas veiksmas.';
  end if;
  return v;
end $$;
grant execute on function public.invoice_office(uuid, text, text, text) to authenticated;

notify pgrst, 'reload schema';
