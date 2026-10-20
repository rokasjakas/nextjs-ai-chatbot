-- ============================================================
-- Konstruktorius (Sistema → Puslapiai): Super Admin pats kuria puslapius
--  * custom_pages – puslapis: pavadinimas, ikona, kam rodomas (rolės), ar paskelbtas, ir jo turinys (kadrai, elementai,
--    paspaudimų veiksmai, perėjimai) – doc (jsonb)
--  * custom_pages_log – kiekvieno išsaugojimo versija, kad būtų galima grąžinti
--  * mato: paskelbtą – nariai, kurių rolė pažymėta (tuščia – visi patvirtinti), Admin – visus paskelbtus,
--    Super Admin – visus; keisti – tik Super Admin
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.custom_pages (
  id           uuid primary key default gen_random_uuid(),
  title        text not null default 'Naujas puslapis' check (length(title) between 1 and 60),
  icon         text,
  roles        text[] not null default '{}',
  published    boolean not null default false,
  sort         int not null default 0,
  doc          jsonb not null default '{}'::jsonb check (pg_column_size(doc) < 6000000),
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),
  updated_by   uuid,
  updated_name text
);
create table if not exists public.custom_pages_log (
  id      bigserial primary key,
  page_id uuid not null,
  title   text,
  doc     jsonb,
  at      timestamptz not null default now(),
  by      uuid,
  name    text
);
create index if not exists custom_pages_log_page_idx on public.custom_pages_log (page_id, at desc);

create or replace function public.is_super() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((select level = 'super' from public.profiles where id = auth.uid()), false)
$$;
grant execute on function public.is_super() to authenticated;

alter table public.custom_pages enable row level security;
drop policy if exists "custom pages read" on public.custom_pages;
create policy "custom pages read" on public.custom_pages for select to authenticated using (
  public.is_super()
  or (published and exists (select 1 from public.profiles p where p.id = auth.uid()
        and p.role not in ('pending','blocked') and (p.role = 'admin' or cardinality(custom_pages.roles) = 0 or p.role = any(custom_pages.roles)))));
drop policy if exists "custom pages super write" on public.custom_pages;
create policy "custom pages super write" on public.custom_pages for all to authenticated using (public.is_super()) with check (public.is_super());
grant select, insert, update, delete on public.custom_pages to authenticated;

alter table public.custom_pages_log enable row level security;
drop policy if exists "custom pages log super" on public.custom_pages_log;
create policy "custom pages log super" on public.custom_pages_log for select to authenticated using (public.is_super());
grant select on public.custom_pages_log to authenticated;
revoke insert, update, delete on public.custom_pages_log from anon, authenticated;

-- kiekvienas išsaugojimas – nauja versija istorijoje (laikoma 50 paskutinių kiekvienam puslapiui)
create or replace function public.custom_pages_keep() returns trigger
  language plpgsql security definer set search_path = public as $$
declare who text;
begin
  select nullif(btrim(coalesce(first_name, '')||' '||coalesce(last_name, '')), '') into who from public.profiles where id = auth.uid();
  new.updated_at := now(); new.updated_by := auth.uid(); new.updated_name := who;
  if tg_op = 'UPDATE' and new.doc is distinct from old.doc then
    insert into public.custom_pages_log (page_id, title, doc, by, name) values (old.id, old.title, old.doc, old.updated_by, old.updated_name);
    delete from public.custom_pages_log where page_id = old.id and id not in
      (select id from public.custom_pages_log where page_id = old.id order by at desc limit 50);
  end if;
  return new;
end $$;
drop trigger if exists custom_pages_keep on public.custom_pages;
create trigger custom_pages_keep before insert or update on public.custom_pages for each row execute function public.custom_pages_keep();

-- serverio funkcijoms ir kopijoms (nuo 2026-10-30 Supabase pats nebeduoda)
grant select, insert, update, delete on public.custom_pages, public.custom_pages_log to service_role;
grant usage, select on sequence public.custom_pages_log_id_seq to service_role;
