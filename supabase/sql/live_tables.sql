-- Gyvi pakeitimai (Supabase realtime): renginiai, paėmimai, išdavimai, darbų apskaita – kolegos pakeitimai matomi iš karto.
-- Saugu paleisti pakartotinai.
do $$ declare t text; begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    foreach t in array array['events', 'rentals', 'handovers', 'work_items'] loop
      if exists (select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = t and c.relkind = 'r')
         and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
        execute format('alter publication supabase_realtime add table public.%I', t);
      end if;
    end loop;
  end if;
end $$;
select tablename as k, 'realtime' as v from pg_publication_tables
 where pubname = 'supabase_realtime' and schemaname = 'public' and tablename in ('events', 'rentals', 'handovers', 'work_items');
