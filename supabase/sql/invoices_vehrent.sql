-- ============================================================
-- Sąskaitos → „Transporto nuoma“
--  * nauja sąskaitų rūšis 'vehrent' – automobilių, mikroautobusų, fūrų nuomos sąskaitos
--  * plates – sąskaitoje rasti valstybiniai numeriai (įkeliant nuskaitomi iš PDF, galima pataisyti)
--  * vehrent_invoices(nuo, iki) – Ataskaitos → Transporto nuoma: visos tokios sąskaitos (nesvarbu, patvirtintos ar ne);
--    mato tie, kas mato Renginius ar Transportą, ir Admin+
-- Reikia: invoices.sql, invoice_check.sql. Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.invoices drop constraint if exists invoices_kind_check;
alter table public.invoices add constraint invoices_kind_check check (kind in ('freelance','service','rent','purchase','other','vehrent'));
alter table public.invoices add column if not exists plates text[] not null default '{}';

-- the office may set this kind too (invoice_office keeps its own list of kinds)
do $$ declare f record; d text; begin
  for f in select p.oid from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.proname = 'invoice_office' loop
    d := pg_get_functiondef(f.oid);
    if position('''vehrent''' in d) = 0 and position($q$('freelance','service','rent','purchase','other')$q$ in d) > 0 then
      execute replace(d, $q$('freelance','service','rent','purchase','other')$q$, $q$('freelance','service','rent','purchase','other','vehrent')$q$);
    end if;
  end loop;
end $$;

create or replace function public.vehrent_invoices(p_from date, p_to date) returns setof jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', i.id, 'supplier', i.supplier, 'number', i.number, 'amount', i.amount, 'invoice_date', i.invoice_date,
                            'created_at', i.created_at, 'status', i.status, 'plates', i.plates, 'note', i.note)
    from public.invoices i
   where i.kind = 'vehrent'
     and coalesce(i.invoice_date, (i.created_at at time zone 'Europe/Vilnius')::date) between p_from and p_to
     and (public.is_plus() or public.can_view('events') or public.can_view('fleet'))
   order by coalesce(i.invoice_date, (i.created_at at time zone 'Europe/Vilnius')::date)
$$;
revoke all on function public.vehrent_invoices(date, date) from public, anon;
grant execute on function public.vehrent_invoices(date, date) to authenticated;

notify pgrst, 'reload schema';
