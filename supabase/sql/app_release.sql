-- ============================================================
-- Atnaujinimų išleidimas: nauja programėlės versija pirma rodoma tik Super Admin,
-- kitiems – tik kai Super Admin „Atnaujinimuose“ paspaudžia „Išleisti visiems“
--  * app_release (viena eilutė) – kuri versija išleista visiems (skaito visi, net neprisijungę – programėlės darbuotojas)
--  * app_release_set(p_version) – išleisti gali tik Super Admin (profiles.level = 'super')
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.app_release (
  id            int primary key default 1 check (id = 1),
  version       text not null check (version ~ '^v[0-9]+$'),
  released_at   timestamptz not null default now(),
  released_by   uuid,
  released_name text
);
-- pradžia: dabartinė versija jau išleista visiems
insert into public.app_release (id, version) values (1, 'v448') on conflict (id) do nothing;

alter table public.app_release enable row level security;
drop policy if exists "app release read" on public.app_release;
create policy "app release read" on public.app_release for select to anon, authenticated using (true);
grant select on public.app_release to anon, authenticated;
revoke insert, update, delete on public.app_release from anon, authenticated;

create or replace function public.app_release_set(p_version text) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare me public.profiles; cur text;
begin
  select * into me from public.profiles where id = auth.uid();
  if me.id is null or coalesce(me.level, '') <> 'super' then return jsonb_build_object('error', 'Išleisti gali tik Super Admin.'); end if;
  if coalesce(p_version, '') !~ '^v[0-9]+$' then return jsonb_build_object('error', 'Neteisinga versija.'); end if;
  select version into cur from public.app_release where id = 1;
  if cur is not null and substring(cur from 2)::int >= substring(p_version from 2)::int then
    return jsonb_build_object('error', 'Versija '||p_version||' jau išleista (visiems – '||cur||').');
  end if;
  insert into public.app_release (id, version, released_at, released_by, released_name)
    values (1, p_version, now(), me.id, nullif(btrim(coalesce(me.first_name, '')||' '||coalesce(me.last_name, '')), ''))
    on conflict (id) do update set version = excluded.version, released_at = excluded.released_at,
      released_by = excluded.released_by, released_name = excluded.released_name;
  return (select to_jsonb(r) from public.app_release r where id = 1);
end $$;
revoke all on function public.app_release_set(text) from public, anon;
grant execute on function public.app_release_set(text) to authenticated;

notify pgrst, 'reload schema';
