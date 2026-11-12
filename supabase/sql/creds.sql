-- ============================================================
-- „Prisijungimai / Kontaktai“
--  * keturios grafos: Programų prisijungimai (app), Puslapių prisijungimai (web), Kontaktai (contact), El. paštai (email)
--  * mato ir tvarko Office, Projektų vadovai ir Admin; El. paštus – tik Admin
--  * slaptažodžiai saugomi UŽŠIFRUOTI (pgcrypto); sąraše jų nėra – atskleidžiami tik paspaudus akutę,
--    kiekvienas atskleidimas įrašomas (cred_access: kas ir kada)
--  * lentelės tiesiogiai nepasiekiamos – tik per funkcijas cred_list / cred_secret / cred_save / cred_delete
-- Reikia: user_roles.sql (my_role). Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
create extension if not exists pgcrypto with schema extensions;
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

-- the encryption key: made once, here in the database, never sent anywhere
create table if not exists private.cred_key (id int primary key default 1 check (id = 1), k text not null);
insert into private.cred_key (id, k) values (1, encode(extensions.gen_random_bytes(32), 'hex')) on conflict (id) do nothing;
revoke all on private.cred_key from public, anon, authenticated;

create table if not exists public.cred_entries (
  id           uuid primary key default gen_random_uuid(),
  cat          text not null check (cat in ('app','web','contact','email')),
  title        text not null default '',     -- programa / puslapis / vardas / el. pašto adresas
  url          text not null default '',
  login        text not null default '',     -- prisijungimo vardas
  secret_enc   bytea,                        -- slaptažodis (užšifruotas)
  company      text not null default '',
  phone        text not null default '',
  email        text not null default '',
  note         text not null default '',
  created_by   uuid default auth.uid(),
  created_at   timestamptz not null default now(),
  updated_by   uuid,
  updated_name text,
  updated_at   timestamptz not null default now()
);
create index if not exists cred_entries_cat on public.cred_entries (cat, lower(title));
alter table public.cred_entries enable row level security;
revoke all on public.cred_entries from anon, authenticated;

create table if not exists public.cred_access (
  id        bigserial primary key,
  entry_id  uuid references public.cred_entries(id) on delete cascade,
  user_id   uuid,
  user_name text,
  at        timestamptz not null default now()
);
alter table public.cred_access enable row level security;
revoke all on public.cred_access from anon, authenticated;

-- who may: Office and up; El. paštai – Admin only
create or replace function public.cred_can(p_cat text) returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','pm','office'), false) and (p_cat <> 'email' or coalesce(public.my_role() = 'admin', false))
$$;
grant execute on function public.cred_can(text) to authenticated;

create or replace function public.cred_list(p_cat text) returns setof jsonb
  language sql stable security definer set search_path = public as $$
  select jsonb_build_object('id', e.id, 'cat', e.cat, 'title', e.title, 'url', e.url, 'login', e.login, 'has_secret', e.secret_enc is not null,
           'company', e.company, 'phone', e.phone, 'email', e.email, 'note', e.note, 'updated_name', e.updated_name, 'updated_at', e.updated_at,
           'views', (select count(*) from public.cred_access a where a.entry_id = e.id),
           'last_view', (select jsonb_build_object('who', a.user_name, 'at', a.at) from public.cred_access a where a.entry_id = e.id order by a.at desc limit 1))
    from public.cred_entries e
   where e.cat = p_cat and public.cred_can(p_cat)
   order by lower(e.title)
$$;

create or replace function public.cred_secret(p_id uuid) returns text
  language plpgsql security definer set search_path = public, extensions as $$
declare e public.cred_entries; k text;
begin
  select * into e from public.cred_entries where id = p_id;
  if e.id is null or not public.cred_can(e.cat) then raise exception 'Nėra teisės.'; end if;
  if e.secret_enc is null then return ''; end if;
  select ck.k into k from private.cred_key ck where ck.id = 1;
  insert into public.cred_access (entry_id, user_id, user_name) values (e.id, auth.uid(), (select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid()));
  return extensions.pgp_sym_decrypt(e.secret_enc, k);
end $$;

-- p_secret: null – the password stays as it is, '' – removed, other – the new one
create or replace function public.cred_save(p_id uuid, p_cat text, p_data jsonb, p_secret text) returns jsonb
  language plpgsql security definer set search_path = public, extensions as $$
declare e public.cred_entries; k text; f text; d jsonb := coalesce(p_data, '{}'::jsonb);
begin
  if not public.cred_can(p_cat) then raise exception 'Nėra teisės.'; end if;
  foreach f in array array['title','url','login','company','phone','email','note'] loop
    if length(coalesce(d ->> f, '')) > 2000 then raise exception 'Per ilgas laukas: %', f; end if;
  end loop;
  select ck.k into k from private.cred_key ck where ck.id = 1;
  if p_id is null then
    insert into public.cred_entries (cat, title, url, login, company, phone, email, note, secret_enc, created_by, updated_by, updated_name)
    values (p_cat, coalesce(d->>'title',''), coalesce(d->>'url',''), coalesce(d->>'login',''), coalesce(d->>'company',''), coalesce(d->>'phone',''),
            coalesce(d->>'email',''), coalesce(d->>'note',''),
            case when coalesce(p_secret,'') = '' then null else extensions.pgp_sym_encrypt(p_secret, k) end, auth.uid(), auth.uid(), (select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid()))
    returning * into e;
  else
    select * into e from public.cred_entries where id = p_id for update;
    if e.id is null or not public.cred_can(e.cat) then raise exception 'Nėra teisės.'; end if;
    update public.cred_entries set title = coalesce(d->>'title',''), url = coalesce(d->>'url',''), login = coalesce(d->>'login',''),
      company = coalesce(d->>'company',''), phone = coalesce(d->>'phone',''), email = coalesce(d->>'email',''), note = coalesce(d->>'note',''),
      secret_enc = case when p_secret is null then secret_enc when p_secret = '' then null else extensions.pgp_sym_encrypt(p_secret, k) end,
      updated_by = auth.uid(), updated_name = (select coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) from public.profiles p where p.id = auth.uid()), updated_at = now()
    where id = p_id returning * into e;
  end if;
  return jsonb_build_object('id', e.id);
end $$;

create or replace function public.cred_delete(p_id uuid) returns void
  language plpgsql security definer set search_path = public as $$
declare e public.cred_entries;
begin
  select * into e from public.cred_entries where id = p_id;
  if e.id is null or not public.cred_can(e.cat) then raise exception 'Nėra teisės.'; end if;
  delete from public.cred_entries where id = p_id;
end $$;

revoke all on function public.cred_list(text), public.cred_secret(uuid), public.cred_save(uuid, text, jsonb, text), public.cred_delete(uuid) from public, anon;
grant execute on function public.cred_list(text), public.cred_secret(uuid), public.cred_save(uuid, text, jsonb, text), public.cred_delete(uuid) to authenticated;

notify pgrst, 'reload schema';
