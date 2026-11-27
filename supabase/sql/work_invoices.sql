-- Darbų apskaita (2 etapas): sąskaita ↔ darbai. Viena sąskaita – keli darbai (ir keli renginiai); suma paskirstoma
-- tiksliai pagal kiekvieno darbo sumą. Darbo būsena seka sąskaitą: pateikta → „Sąskaita gauta“, patvirtinta →
-- „Patvirtinta“, apmokėta → „Apmokėta“; netvirtinta ar ištrinta → darbas vėl laukia sąskaitos.

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'work_items_invoice_fk') then
    update public.work_items w set invoice_id = null where invoice_id is not null and not exists (select 1 from public.invoices i where i.id = w.invoice_id);
    alter table public.work_items add constraint work_items_invoice_fk foreign key (invoice_id) references public.invoices(id) on delete set null;
  end if;
end $$;
create index if not exists work_items_invoice_idx on public.work_items (invoice_id);

-- the agreed sum of a work item (as the app counts it)
create or replace function public.wi_total(w public.work_items) returns numeric
  language sql immutable as $$
  select case when w.pay_type = 'hour' then (case when w.hours is not null and w.rate is not null then w.hours * w.rate end)
              else coalesce(w.amount, case when w.pay_type = 'day' then w.rate end) end
         + coalesce((select sum(nullif(x->>'sum', '')::numeric) from jsonb_array_elements(coalesce(w.extras, '[]'::jsonb)) x), 0)
$$;

-- the invoice's state → its works
create or replace function public.wi_status_of(inv_status text) returns text
  language sql immutable as $$
  select case inv_status when 'paid' then 'paid' when 'approved' then 'approved' when 'sent' then 'approved' when 'queued' then 'approved' else 'invoiced' end
$$;

-- a person's works still waiting for an invoice (done, or planned and already past), or already on this invoice
create or replace function public.wi_open_works(p_contact text, p_name text, p_inv uuid default null)
  returns table (id uuid, work_date date, kind text, pos text, event_id text, event_name text, place text, total numeric, invoice_id uuid, status text)
  language sql stable security definer set search_path = public as $$
  with who as (select coalesce(nullif(p_contact, ''), (select c.id from public.wi_contact(p_name) c)) as cid)
  select w.id, w.work_date, w.kind, w.pos, w.event_id,
         coalesce(case when e.data->>'kind' = 'work' then coalesce(e.data->>'title', 'Sandėlio darbai') else e.data->>'name' end, '') as event_name,
         w.place, round(public.wi_total(w), 2), w.invoice_id, w.status
    from public.work_items w left join public.events e on e.id = w.event_id, who
   where ((who.cid is not null and w.contact_id = who.cid) or (coalesce(p_name, '') <> '' and public.wi_norm(w.person) = public.wi_norm(p_name)))
     and w.status <> 'cancelled'
     and ((w.invoice_id is null and w.status in ('done', 'planned') and w.work_date <= (now() at time zone 'Europe/Vilnius')::date)
          or (p_inv is not null and w.invoice_id = p_inv))
   order by w.work_date, w.id
$$;
revoke all on function public.wi_open_works(text, text, uuid) from public, anon;
grant execute on function public.wi_open_works(text, text, uuid) to authenticated;   -- the app (rates_access) / the portal (service)

-- link: these works are on this invoice (the ones that were on it and are not any more – back to waiting)
create or replace function public.wi_link_invoice(p_inv uuid, p_ids uuid[]) returns integer
  language plpgsql security definer set search_path = public as $$
declare st text; n int;
begin
  if auth.uid() is not null and not public.rates_access() then raise exception 'Tik Office, PV ir Admin.'; end if;
  select status into st from public.invoices where id = p_inv;
  if st is null then raise exception 'Sąskaita nerasta.'; end if;
  update public.work_items set invoice_id = null, status = 'done', updated_at = now()
   where invoice_id = p_inv and not (id = any(coalesce(p_ids, '{}')));
  update public.work_items set invoice_id = p_inv, status = case when st = 'rejected' then 'invoiced' else public.wi_status_of(st) end, updated_at = now()
   where id = any(coalesce(p_ids, '{}')) and (invoice_id is null or invoice_id = p_inv) and status <> 'cancelled';
  get diagnostics n = row_count;
  return n;
end $$;
revoke all on function public.wi_link_invoice(uuid, uuid[]) from public, anon;
grant execute on function public.wi_link_invoice(uuid, uuid[]) to authenticated;

-- the invoice changes: its works follow; not approved – the works wait again
create or replace function public.invoices_work_items_trg() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'DELETE' then
    update public.work_items set invoice_id = null, status = 'done', updated_at = now() where invoice_id = old.id;
    return old;
  end if;
  if new.status is distinct from old.status then
    if new.status = 'rejected' then
      update public.work_items set invoice_id = null, status = 'done', updated_at = now() where invoice_id = new.id;
    else
      update public.work_items set status = public.wi_status_of(new.status), updated_at = now() where invoice_id = new.id and status <> 'cancelled';
    end if;
  end if;
  return new;
exception when others then
  raise warning 'invoices → work_items: %', sqlerrm;
  return coalesce(new, old);
end $$;
drop trigger if exists invoices_work_items on public.invoices;
create trigger invoices_work_items after update of status on public.invoices for each row execute function public.invoices_work_items_trg();
drop trigger if exists invoices_work_items_del on public.invoices;
create trigger invoices_work_items_del before delete on public.invoices for each row execute function public.invoices_work_items_trg();

notify pgrst, 'reload schema';
select 'darbai su sąskaita' as k, count(*)::text as v from public.work_items where invoice_id is not null
union all select 'laukia sąskaitos (atlikti)', count(*)::text from public.work_items where invoice_id is null and status = 'done';
