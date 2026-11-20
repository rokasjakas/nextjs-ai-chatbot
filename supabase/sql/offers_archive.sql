-- ============================================================
-- offers_archive.sql — pasiūlymų archyvas (atsarginis dublikatas)
--  * kiekvienas pasiūlymo pakeitimas palieka ankstesnės būsenos kopiją (kind 'save'; ne dažniau kaip kas 5 min.,
--    paskutinės 20 kiekvienam pasiūlymui);
--  * ištrinta versija (kind 'version') ir ištrintas pasiūlymas (kind 'deleted') išsaugomi visam laikui;
--  * viskas daroma duomenų bazėje (trigeris), tad nesvarbu, iš kur ištrinta;
--  * offer_restore(id) – grąžina ištrintą pasiūlymą, versiją arba seną būseną (kaip kopiją). Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.offers_archive (
  id        bigserial primary key,
  offer_id  uuid not null,
  kind      text not null check (kind in ('save','version','deleted')),
  title     text,
  client    text,
  versions  int,
  data      jsonb,            -- 'version': the version itself; others: null (the whole row is in row_data)
  row_data  jsonb,            -- the whole offers row as it was
  by_id     uuid default auth.uid(),
  by_name   text,
  at        timestamptz not null default now(),
  restored_at timestamptz,
  restored_by text
);
create index if not exists offers_archive_offer_idx on public.offers_archive (offer_id, kind, at desc);
create index if not exists offers_archive_kind_idx on public.offers_archive (kind, at desc);
alter table public.offers_archive enable row level security;
drop policy if exists "view offers archive" on public.offers_archive;
create policy "view offers archive" on public.offers_archive for select to authenticated using (public.can_view('offers'));
-- no insert / update / delete for members: only the trigger and offer_restore write here

create or replace function public.offers_archive_who() returns text
language sql stable security definer set search_path = public as $$
  select coalesce(nullif(trim(concat_ws(' ', first_name, last_name)), ''), email) from public.profiles where id = auth.uid()
$$;

create or replace function public.offers_archive_trg() returns trigger
language plpgsql security definer set search_path = public as $$
declare who text := public.offers_archive_who(); v jsonb; keep int := 20;
begin
  if tg_op = 'DELETE' then
    insert into public.offers_archive (offer_id, kind, title, client, versions, row_data, by_name)
      values (old.id, 'deleted', old.title, old.client, coalesce(jsonb_array_length(old.data->'versions'), 0), to_jsonb(old), coalesce(who, old.updated_by));
    return old;
  end if;
  if old.data is not distinct from new.data then return new; end if;
  -- versions that are gone
  for v in select x from jsonb_array_elements(coalesce(old.data->'versions', '[]'::jsonb)) x
           where not exists (select 1 from jsonb_array_elements(coalesce(new.data->'versions', '[]'::jsonb)) y where y->'n' = x->'n') loop
    insert into public.offers_archive (offer_id, kind, title, client, versions, data, row_data, by_name)
      values (old.id, 'version', old.title, old.client, coalesce(jsonb_array_length(old.data->'versions'), 0), v, to_jsonb(old), coalesce(who, new.updated_by));
  end loop;
  -- the state before this save (at most every 5 minutes; the newest 20)
  if not exists (select 1 from public.offers_archive where offer_id = old.id and kind = 'save' and at > now() - interval '5 minutes') then
    insert into public.offers_archive (offer_id, kind, title, client, versions, row_data, by_name)
      values (old.id, 'save', old.title, old.client, coalesce(jsonb_array_length(old.data->'versions'), 0), to_jsonb(old), coalesce(old.updated_by, who));
    delete from public.offers_archive a where a.offer_id = old.id and a.kind = 'save'
      and a.id not in (select id from public.offers_archive where offer_id = old.id and kind = 'save' order by at desc limit keep);
  end if;
  return new;
end $$;
drop trigger if exists offers_archive_trg on public.offers;
create trigger offers_archive_trg before update or delete on public.offers for each row execute function public.offers_archive_trg();

-- give back: a deleted offer (as it was), a deleted version (into its offer), an earlier state (as a new copy)
create or replace function public.offer_restore(p_id bigint) returns jsonb
language plpgsql security definer set search_path = public as $$
declare a public.offers_archive; r public.offers; nid uuid; vs jsonb; v jsonb; n int; who text := public.offers_archive_who();
begin
  if not public.can_edit('offers') then raise exception 'Nėra teisės atkurti pasiūlymų.'; end if;
  select * into a from public.offers_archive where id = p_id;
  if a.id is null then raise exception 'Archyvo įrašas nerastas.'; end if;
  if a.kind = 'deleted' then
    if exists (select 1 from public.offers where id = a.offer_id) then raise exception 'Šis pasiūlymas jau yra sąraše.'; end if;
    r := jsonb_populate_record(null::public.offers, a.row_data);
    insert into public.offers select r.*;
    update public.offers_archive set restored_at = now(), restored_by = who where id = p_id;
    return jsonb_build_object('offer_id', a.offer_id, 'kind', 'deleted');
  elsif a.kind = 'version' then
    if not exists (select 1 from public.offers where id = a.offer_id) then raise exception 'Pasiūlymas ištrintas – pirma atkurk jį (skiltyje „Ištrinti pasiūlymai“).'; end if;
    select coalesce(data->'versions', '[]'::jsonb) into vs from public.offers where id = a.offer_id;
    v := a.data;
    if exists (select 1 from jsonb_array_elements(vs) y where y->'n' = v->'n') then
      select coalesce(max((y->>'n')::int), 0) + 1 into n from jsonb_array_elements(vs) y;
      v := jsonb_set(jsonb_set(v, '{n}', to_jsonb(n)), '{name}', to_jsonb(coalesce(v->>'name', 'V') || ' (atkurta)'));
    end if;
    update public.offers set data = jsonb_set(data, '{versions}', (select coalesce(jsonb_agg(x order by (x->>'n')::int), '[]'::jsonb) from jsonb_array_elements(vs || jsonb_build_array(v)) x)),
      updated_at = now(), updated_by = coalesce(who, updated_by) where id = a.offer_id;
    update public.offers_archive set restored_at = now(), restored_by = who where id = p_id;
    return jsonb_build_object('offer_id', a.offer_id, 'kind', 'version', 'n', v->'n');
  else
    nid := gen_random_uuid();
    r := jsonb_populate_record(null::public.offers, a.row_data);
    r.id := nid; r.title := coalesce(r.title, '') || ' (atkurta ' || to_char(a.at at time zone 'Europe/Vilnius', 'YYYY-MM-DD HH24:MI') || ')';
    r.data := jsonb_set(r.data, '{project}', to_jsonb(r.title)); r.status := 'draft'; r.job_id := null; r.updated_at := now(); r.updated_by := coalesce(who, r.updated_by);
    insert into public.offers select r.*;
    update public.offers_archive set restored_at = now(), restored_by = who where id = p_id;
    return jsonb_build_object('offer_id', nid, 'kind', 'save');
  end if;
end $$;
revoke all on function public.offer_restore(bigint) from public, anon;
grant execute on function public.offer_restore(bigint) to authenticated;
grant select on public.offers_archive to authenticated;
notify pgrst, 'reload schema';
