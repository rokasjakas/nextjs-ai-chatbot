-- ============================================================
-- Sistema → Nustatymai: programos nustatymai be kodo
--  * app_config – nustatymai, kuriuos programa nuskaito paleidžiant (pvz. 'nav': puslapių pavadinimai, ikonos,
--    meniu tvarka, išjungti puslapiai). Skaito visi prisijungę, keisti gali tik Super Admin per app_config_set.
--  * app_config_log – kiekvieno pakeitimo istorija (kas, kada, kas buvo prieš tai), kad būtų galima grąžinti.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.app_config (
  key          text primary key check (key ~ '^[a-z_]{1,40}$'),
  value        jsonb not null default '{}'::jsonb,
  updated_at   timestamptz not null default now(),
  updated_by   uuid,
  updated_name text
);
create table if not exists public.app_config_log (
  id    bigserial primary key,
  key   text not null,
  value jsonb,
  prev  jsonb,
  at    timestamptz not null default now(),
  by    uuid,
  name  text,
  note  text
);
create index if not exists app_config_log_at_idx on public.app_config_log (at desc);

create or replace function public.is_super() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select level = 'super' from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.is_super() to authenticated;

alter table public.app_config enable row level security;
drop policy if exists "app config read" on public.app_config;
create policy "app config read" on public.app_config for select to authenticated using (true);
grant select on public.app_config to authenticated;
revoke insert, update, delete on public.app_config from anon, authenticated;

alter table public.app_config_log enable row level security;
drop policy if exists "app config log super read" on public.app_config_log;
create policy "app config log super read" on public.app_config_log for select to authenticated using (public.is_super());
grant select on public.app_config_log to authenticated;
revoke insert, update, delete on public.app_config_log from anon, authenticated;

-- keisti – tik Super Admin; kiekvienas pakeitimas įrašomas į istoriją
create or replace function public.app_config_set(p_key text, p_value jsonb, p_note text default null) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare me public.profiles; old jsonb; who text;
begin
  select * into me from public.profiles where id = auth.uid();
  if me.id is null or coalesce(me.level, '') <> 'super' then return jsonb_build_object('error', 'Keisti gali tik Super Admin.'); end if;
  if coalesce(p_key, '') !~ '^[a-z_]{1,40}$' then return jsonb_build_object('error', 'Neteisingas raktas.'); end if;
  if p_value is null or jsonb_typeof(p_value) <> 'object' then return jsonb_build_object('error', 'Reikšmė turi būti objektas.'); end if;
  if pg_column_size(p_value) > 200000 then return jsonb_build_object('error', 'Per dideli nustatymai.'); end if;
  who := nullif(btrim(coalesce(me.first_name, '')||' '||coalesce(me.last_name, '')), '');
  select value into old from public.app_config where key = p_key;
  insert into public.app_config (key, value, updated_at, updated_by, updated_name) values (p_key, p_value, now(), me.id, who)
    on conflict (key) do update set value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by, updated_name = excluded.updated_name;
  insert into public.app_config_log (key, value, prev, by, name, note) values (p_key, p_value, old, me.id, who, left(p_note, 300));
  delete from public.app_config_log where at < now() - interval '365 days';
  return (select to_jsonb(c) from public.app_config c where key = p_key);
end $$;
revoke all on function public.app_config_set(text, jsonb, text) from public, anon;
grant execute on function public.app_config_set(text, jsonb, text) to authenticated;

-- serverio funkcijoms ir kopijoms (nuo 2026-10-30 Supabase pats nebeduoda)
grant select, insert, update, delete on public.app_config, public.app_config_log to service_role;
grant usage, select on sequence public.app_config_log_id_seq to service_role;
