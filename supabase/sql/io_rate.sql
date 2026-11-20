-- Disko apkrovos matavimas per 60 s (tik skaito, nieko nekeičia): kas rašo / skaito diską dabar – pakeitimų žurnalas (WAL),
-- procesai (realtime, autovacuum, checkpointer…), lentelės ir užklausos. Paleidžiama per „SQL paleidimas“.
-- Rezultatas – NOTICE eilutės žurnale.
do $$
declare
  v int := current_setting('server_version_num')::int;
  w0 jsonb; w1 jsonb; d0 jsonb; d1 jsonb; t0 jsonb; t1 jsonb; q0 jsonb; q1 jsonb; io0 jsonb; io1 jsonb; c0 jsonb; c1 jsonb; r record;
begin
  raise notice 'versija % · shared_buffers % · max_wal_size % · checkpoint_timeout % · wal_level %', current_setting('server_version'),
    current_setting('shared_buffers'), current_setting('max_wal_size'), current_setting('checkpoint_timeout'), current_setting('wal_level');
  for r in select usename, application_name, backend_type, state, count(*) n from pg_stat_activity group by 1,2,3,4 order by 5 desc limit 12 loop
    raise notice 'conn · % · % · % · % · %×', r.usename, r.application_name, r.backend_type, r.state, r.n; end loop;

  select to_jsonb(x) into w0 from (select wal_records, wal_fpi, wal_bytes from pg_stat_wal) x;
  select to_jsonb(x) into d0 from (select blks_read, blks_hit, tup_inserted, tup_updated, tup_deleted, temp_bytes, xact_commit from pg_stat_database where datname = current_database()) x;
  select coalesce(jsonb_object_agg(schemaname||'.'||relname, n_tup_ins + n_tup_upd + n_tup_del), '{}') into t0 from pg_stat_all_tables;
  select coalesce(jsonb_object_agg(queryid::text, jsonb_build_array(shared_blks_read + shared_blks_written + temp_blks_written, wal_bytes, calls)), '{}') into q0 from pg_stat_statements;
  if v >= 160000 then
    execute $q$select coalesce(jsonb_object_agg(backend_type||'/'||object||'/'||context, jsonb_build_array(coalesce(reads,0), coalesce(writes,0), coalesce(extends,0), coalesce(fsyncs,0))), '{}') from pg_stat_io$q$ into io0;
  end if;
  if v >= 170000 then execute $q$select to_jsonb(x) from (select num_timed, num_requested, buffers_written from pg_stat_checkpointer) x$q$ into c0;
  else execute $q$select to_jsonb(x) from (select checkpoints_timed as num_timed, checkpoints_req as num_requested, buffers_checkpoint as buffers_written from pg_stat_bgwriter) x$q$ into c0; end if;

  perform pg_sleep(60);
  perform pg_stat_clear_snapshot();   -- within one transaction the statistics are otherwise read once and kept

  select to_jsonb(x) into w1 from (select wal_records, wal_fpi, wal_bytes from pg_stat_wal) x;
  select to_jsonb(x) into d1 from (select blks_read, blks_hit, tup_inserted, tup_updated, tup_deleted, temp_bytes, xact_commit from pg_stat_database where datname = current_database()) x;
  select coalesce(jsonb_object_agg(schemaname||'.'||relname, n_tup_ins + n_tup_upd + n_tup_del), '{}') into t1 from pg_stat_all_tables;
  select coalesce(jsonb_object_agg(queryid::text, jsonb_build_array(shared_blks_read + shared_blks_written + temp_blks_written, wal_bytes, calls)), '{}') into q1 from pg_stat_statements;
  if v >= 160000 then
    execute $q$select coalesce(jsonb_object_agg(backend_type||'/'||object||'/'||context, jsonb_build_array(coalesce(reads,0), coalesce(writes,0), coalesce(extends,0), coalesce(fsyncs,0))), '{}') from pg_stat_io$q$ into io1;
  end if;
  if v >= 170000 then execute $q$select to_jsonb(x) from (select num_timed, num_requested, buffers_written from pg_stat_checkpointer) x$q$ into c1;
  else execute $q$select to_jsonb(x) from (select checkpoints_timed as num_timed, checkpoints_req as num_requested, buffers_checkpoint as buffers_written from pg_stat_bgwriter) x$q$ into c1; end if;

  raise notice 'per 60 s · WAL % (% įrašų, % pilnų puslapių) · disko skaitymai % · įt % / atn % / ištr % · laikini % · transakcijos %',
    pg_size_pretty(((w1->>'wal_bytes')::numeric - (w0->>'wal_bytes')::numeric)::bigint), (w1->>'wal_records')::bigint - (w0->>'wal_records')::bigint,
    (w1->>'wal_fpi')::bigint - (w0->>'wal_fpi')::bigint, (d1->>'blks_read')::bigint - (d0->>'blks_read')::bigint,
    (d1->>'tup_inserted')::bigint - (d0->>'tup_inserted')::bigint, (d1->>'tup_updated')::bigint - (d0->>'tup_updated')::bigint,
    (d1->>'tup_deleted')::bigint - (d0->>'tup_deleted')::bigint, pg_size_pretty((d1->>'temp_bytes')::bigint - (d0->>'temp_bytes')::bigint),
    (d1->>'xact_commit')::bigint - (d0->>'xact_commit')::bigint;
  raise notice 'checkpoint · laiku % · priverstinai % · įrašyta blokų %', (c1->>'num_timed')::bigint - (c0->>'num_timed')::bigint,
    (c1->>'num_requested')::bigint - (c0->>'num_requested')::bigint, (c1->>'buffers_written')::bigint - (c0->>'buffers_written')::bigint;

  if io1 is not null then
    for r in select k, (io1->k->>0)::bigint - coalesce((io0->k->>0)::bigint,0) rd, (io1->k->>1)::bigint - coalesce((io0->k->>1)::bigint,0) wr,
                    (io1->k->>2)::bigint - coalesce((io0->k->>2)::bigint,0) ex, (io1->k->>3)::bigint - coalesce((io0->k->>3)::bigint,0) fs
             from jsonb_object_keys(io1) k order by 2+3 desc loop
      exit when r.rd + r.wr + r.ex + r.fs = 0;
      raise notice 'io · % · skait % · rašo % · plečia % · fsync %', r.k, r.rd, r.wr, r.ex, r.fs; end loop;
  end if;
  for r in select k, (t1->>k)::bigint - coalesce((t0->>k)::bigint,0) n from jsonb_object_keys(t1) k order by 2 desc limit 10 loop
    exit when r.n = 0; raise notice 'lentelė · % · % pakeitimų', r.k, r.n; end loop;
  for r in select s.query, (q1->k->>0)::bigint - coalesce((q0->k->>0)::bigint,0) b, (q1->k->>1)::numeric - coalesce((q0->k->>1)::numeric,0) wb,
                  (q1->k->>2)::bigint - coalesce((q0->k->>2)::bigint,0) c
           from jsonb_object_keys(q1) k join pg_stat_statements s on s.queryid::text = k
           order by 3 desc nulls last, 2 desc limit 10 loop
    exit when r.c = 0 and r.b = 0;
    raise notice 'užkl · WAL % · blokų % · %× · %', pg_size_pretty(r.wb::bigint), r.b, r.c, left(regexp_replace(r.query, '\s+', ' ', 'g'), 140); end loop;
end $$;
