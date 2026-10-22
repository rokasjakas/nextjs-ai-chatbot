-- ============================================================
-- Sąskaitos → „Transporto nuoma“: detalizacija
--  * veh_lines – sąskaitos eilutės: kuris transportas (valst. nr.), kas nuomota, nuo kada iki kada, suma
--    [{plate, desc, from, to, qty, total, kind:'rent'|'extra'}]; nuskaitoma iš PDF arba įrašoma ranka
--  * Ataskaitos → Transporto nuoma skaičiuoja kiekvieną automobilį pagal jo eilutę (ne dalijant sumą po lygiai)
-- Reikia: invoices_vehrent.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.invoices add column if not exists veh_lines jsonb;

create or replace function public.vehrent_invoices(p_from date, p_to date) returns setof jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', i.id, 'supplier', i.supplier, 'number', i.number, 'amount', i.amount, 'invoice_date', i.invoice_date,
                            'created_at', i.created_at, 'status', i.status, 'plates', i.plates, 'note', i.note, 'veh_lines', i.veh_lines)
    from public.invoices i
   where i.kind = 'vehrent'
     and coalesce(i.invoice_date, (i.created_at at time zone 'Europe/Vilnius')::date) between p_from and p_to
     and (public.is_plus() or public.can_view('events') or public.can_view('fleet'))
   order by coalesce(i.invoice_date, (i.created_at at time zone 'Europe/Vilnius')::date)
$$;
revoke all on function public.vehrent_invoices(date, date) from public, anon;
grant execute on function public.vehrent_invoices(date, date) to authenticated;

-- the detail written / corrected later (an invoice uploaded before the detail existed): the uploader, Office, Admin+
create or replace function public.invoice_vehlines(p_id uuid, p_lines jsonb) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare v public.invoices; pl text[];
begin
  select * into v from public.invoices where id = p_id for update;
  if v.id is null then raise exception 'Sąskaitos nėra.'; end if;
  if v.kind <> 'vehrent' then raise exception 'Tai ne transporto nuomos sąskaita.'; end if;
  if not (v.created_by = auth.uid() or public.is_plus() or coalesce(public.my_role() in ('admin','office','pm'), false)) then raise exception 'Nėra teisės.'; end if;
  if jsonb_typeof(coalesce(p_lines, '[]'::jsonb)) <> 'array' or jsonb_array_length(coalesce(p_lines, '[]'::jsonb)) > 200 then raise exception 'Netinkama detalizacija.'; end if;
  select coalesce(array_agg(distinct upper(btrim(x ->> 'plate'))) filter (where coalesce(btrim(x ->> 'plate'), '') <> ''), '{}') into pl
    from jsonb_array_elements(coalesce(p_lines, '[]'::jsonb)) x;
  update public.invoices set veh_lines = p_lines, plates = pl where id = p_id returning * into v;
  return to_jsonb(v);
end $$;
revoke all on function public.invoice_vehlines(uuid, jsonb) from public, anon;
grant execute on function public.invoice_vehlines(uuid, jsonb) to authenticated;

notify pgrst, 'reload schema';
