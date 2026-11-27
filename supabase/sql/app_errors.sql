-- ============================================================
-- Sistema: klaidų žurnalas
--  * app_errors – programos klaidos iš visų narių naršyklių ir telefonų
--    (neveikianti lentelė, serverio funkcija, kodo klaida), kad Super Admin „Sistemoje“ matytų, kas ir kur neveikia
--  * įrašyti gali kiekvienas prisijungęs narys (tik savo vardu), skaityti ir trinti – tik Super Admin
--  * senesni nei 30 d. įrašai išsitrina patys
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.app_errors (
  id          bigserial primary key,
  created_at  timestamptz not null default now(),
  user_id     uuid default auth.uid(),
  user_name   text,
  ver         text,
  tab         text,
  kind        text not null default 'js' check (kind in ('js','api','fn','net','check')),
  node        text,
  status      int,
  code        text,
  msg         text,
  detail      text,
  count       int not null default 1,
  ua          text
);
create index if not exists app_errors_created_idx on public.app_errors (created_at desc);
create index if not exists app_errors_node_idx on public.app_errors (node);

-- ilgio ribos, kad žurnalas neišpūstų
alter table public.app_errors drop constraint if exists app_errors_len;
alter table public.app_errors add constraint app_errors_len check (
  coalesce(length(msg), 0) <= 600 and coalesce(length(detail), 0) <= 2000 and coalesce(length(node), 0) <= 120
  and coalesce(length(tab), 0) <= 40 and coalesce(length(ua), 0) <= 200 and count between 1 and 10000);

create or replace function public.is_super() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select level = 'super' from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.is_super() to authenticated;

alter table public.app_errors enable row level security;
drop policy if exists "app errors insert own" on public.app_errors;
create policy "app errors insert own" on public.app_errors for insert to authenticated with check (user_id = auth.uid());
drop policy if exists "app errors super read" on public.app_errors;
create policy "app errors super read" on public.app_errors for select to authenticated using (public.is_super());
drop policy if exists "app errors super delete" on public.app_errors;
create policy "app errors super delete" on public.app_errors for delete to authenticated using (public.is_super());
grant select, insert, delete on public.app_errors to authenticated;
grant usage, select on sequence public.app_errors_id_seq to authenticated;
revoke update on public.app_errors from anon, authenticated;

-- senų įrašų valymas: po kiekvieno įrašymo (pagal datos indeksą – greita, kai nėra ko trinti)
create or replace function public.app_errors_prune() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  delete from public.app_errors where created_at < now() - interval '30 days';
  return null;
end $$;
drop trigger if exists app_errors_prune on public.app_errors;
create trigger app_errors_prune after insert on public.app_errors for each statement execute function public.app_errors_prune();

-- serverio funkcijoms ir kopijoms (nuo 2026-10-30 Supabase pats nebeduoda)
grant select, insert, update, delete on public.app_errors to service_role;
grant usage, select on sequence public.app_errors_id_seq to service_role;
