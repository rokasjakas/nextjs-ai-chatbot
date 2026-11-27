-- Naujas renginys: pastabos, nuorodos ir failai – vieną kartą parašomi renginio Slack kanale (žinutės laikas čia)
alter table public.slack_channels add column if not exists intro_ts text;
notify pgrst, 'reload schema';
select 'intro_ts' as k, count(*)::text as v from information_schema.columns where table_schema = 'public' and table_name = 'slack_channels' and column_name = 'intro_ts';
