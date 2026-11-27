-- ============================================================
-- Kalendorius visiems: renginiai, vykstantys tą dieną, matomi visiems
-- prisijungusiems nariams (net jei jie nemato „Renginių“ skilties) –
-- tik pavadinimas, datos ir vieta, be kitos renginio informacijos.
-- my_roles – kur tu pats įrašytas (komandos lentelėse ar vadovu),
-- atpažįstama pagal vardą ir pavardę arba slapyvardį, kaip programėlėje.
-- Kas atostogauja, grąžina leave_busy() (leave.sql).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create or replace function public.norm_name(t text) returns text
  language sql immutable as $$
  select trim(regexp_replace(regexp_replace(translate(lower(coalesce(t, '')), 'ąčęėįšųūž', 'aceeisuuz'), '[^a-z0-9 ]', ' ', 'g'), '\s+', ' ', 'g'))
$$;

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
     and ev.d1 <= d_to and ev.d2 >= d_from
     and d_to - d_from <= 120
   order by ev.d1, 3
$$;
revoke all on function public.calendar_events(date, date) from public, anon;
grant execute on function public.calendar_events(date, date) to authenticated;
