-- v635: mažiau Disk IO.
--  * Narių nustatymuose (profiles.notify_prefs) per klaidą atsidūrusi chato kopija (chatCache, iki ~1 MB) pašalinama –
--    ji laikoma tik įrenginyje; kiti nustatymai lieka. Nuo v635 programa jos ten nebeįrašo.
--  * mail_index išimama iš realtime (El. pašto puslapis pašalintas v632, lentelė nebenaudojama).
-- Paleidžiama per „SQL paleidimas“. Saugu paleisti pakartotinai.
update public.profiles set notify_prefs = notify_prefs - 'chatCache' where notify_prefs ? 'chatCache';
do $$
begin
  if exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'mail_index') then
    alter publication supabase_realtime drop table public.mail_index;
  end if;
end $$;
select 'prefs' as k, 'su chatCache ' || count(*) filter (where notify_prefs ? 'chatCache') || ' · didž. ' || pg_size_pretty(max(pg_column_size(notify_prefs))::bigint)
  || ' · visi ' || pg_size_pretty(sum(pg_column_size(notify_prefs))::bigint) as v from public.profiles
union all
select 'pub', string_agg(tablename, ', ' order by tablename) from pg_publication_tables where pubname = 'supabase_realtime';
