-- ============================================================
-- Lygių apribojimai (Runner, Freelance, Tech)
--  * Runner ir Freelance: nėra „Prašymų“ (laisvos dienos, atostogos) ir „Pirkinių“ (pasiūlymų)
--  * Freelance: nėra „Inventorizacijos“; „Renginiuose“ (ir kalendoriuje) – tik tie renginiai,
--    kuriuose pats įrašytas (komandos lentelėse ar vadovu), atpažįstama pagal vardą ir pavardę arba slapyvardį
--  * Tech: „Sąskaitose“ – tik savo įkeltos sąskaitos (įkelti gali); „Renginius“ tik mato (nekuria, neredaguoja, netrina)
-- Reikia: user_roles.sql, events_rentals.sql, leave.sql, purchases.sql, stocktake.sql, invoices.sql, calendar_all.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.low_level() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('runner','freelance'), false)
$$;
grant execute on function public.low_level() to authenticated;

-- Prašymai: Runner ir Freelance naujų nepateikia
drop policy if exists "ask leave" on public.leave_requests;
create policy "ask leave" on public.leave_requests for insert to authenticated
  with check (user_id = auth.uid() and public.is_approved() and not public.low_level());

-- Pirkiniai (pasiūlymai): Runner ir Freelance nemato ir nesiūlo
drop policy if exists "proposals view" on public.purchase_proposals;
create policy "proposals view" on public.purchase_proposals for select to authenticated
  using (public.is_approved() and not public.low_level());
drop policy if exists "proposals add" on public.purchase_proposals;
create policy "proposals add" on public.purchase_proposals for insert to authenticated
  with check (public.is_approved() and not public.low_level() and created_by = auth.uid() and status = 'new');

-- Inventorizacija: Runner ir Freelance nemato
drop policy if exists "view stk_items" on public.stk_items;
create policy "view stk_items" on public.stk_items for select to authenticated using (public.can_view('inventory') and not public.low_level());
drop policy if exists "view stk_sessions" on public.stk_sessions;
create policy "view stk_sessions" on public.stk_sessions for select to authenticated using (public.can_view('inventory') and not public.low_level());
drop policy if exists "view stk_log" on public.stk_log;
create policy "view stk_log" on public.stk_log for select to authenticated using (public.can_view('inventory') and not public.low_level());

-- Renginiai: ar aš įrašytas (komandos lentelėse ar vadovu)
create or replace function public.norm_name(t text) returns text
  language sql immutable as $$
  select trim(regexp_replace(regexp_replace(translate(lower(coalesce(t, '')), 'ąčęėįšųūž', 'aceeisuuz'), '[^a-z0-9 ]', ' ', 'g'), '\s+', ' ', 'g'))
$$;
create or replace function public.event_has_me(d jsonb) returns boolean
  language sql stable security definer set search_path = public as $$
  with me as (
    select nullif(public.norm_name(coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.full_name)), '') as n1,
           nullif(public.norm_name(p.nickname), '') as n2
      from public.profiles p where p.id = auth.uid()
  ), who as (
    select en->>'person' as n
      from jsonb_array_elements(case when jsonb_typeof(d->'crew') = 'array' then d->'crew' else '[]'::jsonb end) g,
           jsonb_array_elements(case when jsonb_typeof(g->'entries') = 'array' then g->'entries' else '[]'::jsonb end) en
    union all select d->>'manager'
  )
  select exists (select 1 from me, who where public.norm_name(who.n) <> '' and public.norm_name(who.n) in (me.n1, me.n2))
$$;
grant execute on function public.event_has_me(jsonb) to authenticated;

-- Freelance mato tik savo renginius
drop policy if exists "view events" on public.events;
create policy "view events" on public.events for select to authenticated
  using ((public.can_view('events') or public.can_view('rentals'))
         and (public.my_role() is distinct from 'freelance' or public.event_has_me(data)));

-- kalendorius: Freelance – irgi tik savo renginiai
create or replace function public.calendar_events(d_from date, d_to date)
  returns table (id text, kind text, name text, date_from date, date_to date, venue text, my_roles text[])
  language sql stable security definer set search_path = public as $$
  with me as (
    select public.norm_name(concat_ws(' ', p.first_name, p.last_name)) as n1,
           nullif(public.norm_name(p.nickname), '') as n2
      from public.profiles p where p.id = auth.uid()
  ), ev as (
    select e.id, e.data,
           (e.data->>'date')::date as d1,
           case when coalesce(e.data->>'dateEnd', '') ~ '^\d{4}-\d{2}-\d{2}$' and (e.data->>'dateEnd')::date >= (e.data->>'date')::date
                then (e.data->>'dateEnd')::date else (e.data->>'date')::date end as d2
      from public.events e
     where coalesce(e.data->>'date', '') ~ '^\d{4}-\d{2}-\d{2}$'
       and coalesce(e.data->>'deletedAt', '') = ''
       and coalesce(e.data->>'handoverId', '') = ''
  )
  select ev.id,
         case when ev.data->>'kind' = 'work' then 'work' else 'event' end,
         case when ev.data->>'kind' = 'work' then coalesce(nullif(ev.data->>'title', ''), 'Sandėlio darbai')
              else coalesce(nullif(ev.data->>'name', ''), 'Renginys') end,
         ev.d1, ev.d2,
         nullif(coalesce(nullif(ev.data->>'venue', ''), case when jsonb_typeof(ev.data->'location') = 'string' then ev.data->>'location' end), ''),
         array(
           select concat_ws(' · ', nullif(g->>'title', ''), nullif(en->>'pos', ''))
             from jsonb_array_elements(case when jsonb_typeof(ev.data->'crew') = 'array' then ev.data->'crew' else '[]'::jsonb end) g,
                  jsonb_array_elements(case when jsonb_typeof(g->'entries') = 'array' then g->'entries' else '[]'::jsonb end) en, me
            where public.norm_name(en->>'person') <> '' and public.norm_name(en->>'person') in (me.n1, me.n2)
           union all
           select 'Vadovas' from me
            where public.norm_name(ev.data->>'manager') <> '' and public.norm_name(ev.data->>'manager') in (me.n1, me.n2)
         )
    from ev
   where public.is_approved()
     and (public.my_role() is distinct from 'freelance' or public.event_has_me(ev.data))
     and ev.d1 <= d_to and ev.d2 >= d_from
     and d_to - d_from <= 120
   order by ev.d1, 3
$$;
revoke all on function public.calendar_events(date, date) from public, anon;
grant execute on function public.calendar_events(date, date) to authenticated;

-- Tech: Renginius tik mato
update public.role_permissions set can_view = true, can_edit = false where role = 'tech' and section = 'events';

-- Sąskaitos: be Admin+ (ir ofiso tikrintojų – „invoices check read“) kiekvienas mato tik savo įkeltas
-- (ne gautas per portalą ar el. paštu)
drop policy if exists "invoices read" on public.invoices;
create policy "invoices read" on public.invoices
  for select to authenticated using (public.is_plus() or (created_by = auth.uid() and coalesce(source, '') not in ('portal','email')));

notify pgrst, 'reload schema';
