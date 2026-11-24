-- Google paskyra (Meet) ir susitikimų lentelė – tik skaitymas
select 'auth' as k, email, connected_at from public.google_meet_auth;
select 'cols' as k, table_name, column_name, data_type from information_schema.columns where table_schema='public' and table_name in ('google_meet_auth','meetings') order by table_name, ordinal_position;
select 'meet' as k, id, title, meet_date, scope, online from public.meetings where meet_date >= current_date - 1 order by meet_date limit 5;
