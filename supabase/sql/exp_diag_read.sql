-- Google paskyros leidimai (be el. pašto) – tik skaitymas
select 'auth' as k, connected_at, scope is null as scope_null, length(scope) as scope_len, scope ilike '%%calendar%%' as has_calendar, regexp_replace(coalesce(scope,''), '[^ ]*/auth/', '', 'g') as scopes from public.google_meet_auth;
