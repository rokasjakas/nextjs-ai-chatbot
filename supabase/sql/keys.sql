-- ============================================================
-- Ofisas → „Raktai“
--  * key_codes – sandėlio spynos kodai: sugeneruotas 4 skaitmenų kodas, kas ir kada sugeneravo,
--                kas ir kada pažymėjo, kad kodas ant spynos pakeistas
--  * key_loans – išduoti raktai: kam, kada, kas išdavė; kada grąžintas ir kas pažymėjo
--  * key_code_applied(id) – pažymi „kodas ant spynos pakeistas“ ir įdeda naują kodą
--                kanale #sandėlio-raktas (kanalą sukuria, jei jo nėra; nariai – kas mato „Raktus“)
-- Mato, kas mato „Raktus“ (Admin → teisės); keisti – kas juos redaguoja.
-- Reikia: user_roles.sql, members_chat.sql, chat_slack.sql.
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- skiltis „Raktai“ teisių lentelėje ----------
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people','newproj','invoices','buy','keys'));
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','keys',true,true), ('office','keys',true,true), ('tech','keys',true,true),
  ('freelance','keys',false,false), ('runner','keys',false,false)
on conflict (role, section) do nothing;

create table if not exists public.key_codes (
  id            uuid primary key default gen_random_uuid(),
  code          text not null check (code ~ '^[0-9]{4}$'),
  created_by    uuid default auth.uid(),
  created_name  text,
  created_at    timestamptz not null default now(),
  applied_at    timestamptz,
  applied_by    uuid,
  applied_name  text,
  cancelled_at  timestamptz
);
create index if not exists key_codes_created on public.key_codes (created_at desc);

create table if not exists public.key_loans (
  id             uuid primary key default gen_random_uuid(),
  key_name       text not null default 'Sandėlio raktas',
  holder_id      uuid,
  holder_name    text not null check (length(trim(holder_name)) > 0),
  given_at       timestamptz not null default now(),
  given_by       uuid,
  given_by_name  text,
  note           text not null default '',
  returned_at    timestamptz,
  returned_by    uuid,
  returned_name  text,
  created_by     uuid default auth.uid(),
  created_at     timestamptz not null default now()
);
create index if not exists key_loans_open on public.key_loans (returned_at, given_at desc);

alter table public.key_codes enable row level security;
alter table public.key_loans enable row level security;

drop policy if exists "key codes view" on public.key_codes;
create policy "key codes view" on public.key_codes for select to authenticated using (public.can_view('keys'));
drop policy if exists "key codes add" on public.key_codes;
create policy "key codes add" on public.key_codes for insert to authenticated
  with check (public.can_edit('keys') and applied_at is null);
drop policy if exists "key codes edit" on public.key_codes;
create policy "key codes edit" on public.key_codes for update to authenticated
  using (public.can_edit('keys')) with check (public.can_edit('keys'));
drop policy if exists "key codes remove" on public.key_codes;
create policy "key codes remove" on public.key_codes for delete to authenticated using (public.is_admin());

drop policy if exists "key loans view" on public.key_loans;
create policy "key loans view" on public.key_loans for select to authenticated using (public.can_view('keys'));
drop policy if exists "key loans add" on public.key_loans;
create policy "key loans add" on public.key_loans for insert to authenticated with check (public.can_edit('keys'));
drop policy if exists "key loans edit" on public.key_loans;
create policy "key loans edit" on public.key_loans for update to authenticated
  using (public.can_edit('keys')) with check (public.can_edit('keys'));
drop policy if exists "key loans remove" on public.key_loans;
create policy "key loans remove" on public.key_loans for delete to authenticated using (public.is_admin());

revoke all on public.key_codes, public.key_loans from anon;
grant select, insert, update, delete on public.key_codes, public.key_loans to authenticated;

-- who sees „Raktai“ (for the channel members)
create or replace function public.keys_viewer(uid uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles p where p.id = uid and (
    p.role = 'admin' or exists (select 1 from public.role_permissions rp
                                where rp.role = p.role and rp.section = 'keys' and (rp.can_view or rp.can_edit))))
$$;

-- the code is on the lock now: mark it and post it in #sandėlio-raktas
create or replace function public.key_code_applied(p_id uuid) returns uuid
  language plpgsql security definer set search_path = public as $$
declare k public.key_codes; cid uuid; who text; ts text;
begin
  if not public.can_edit('keys') then raise exception 'Nėra teisės keisti raktų.'; end if;
  select * into k from public.key_codes where id = p_id;
  if k.id is null then raise exception 'Kodas nerastas.'; end if;
  if k.cancelled_at is not null then raise exception 'Šis kodas atšauktas.'; end if;
  select coalesce(nullif(trim(coalesce(p.full_name, concat_ws(' ', p.first_name, p.last_name))), ''), p.email)
    into who from public.profiles p where p.id = auth.uid();
  if k.applied_at is null then
    update public.key_codes set applied_at = now(), applied_by = auth.uid(), applied_name = who where id = p_id
      returning * into k;
    -- older codes not put on the lock are left behind
    update public.key_codes set cancelled_at = now() where applied_at is null and cancelled_at is null and created_at < k.created_at;
  end if;
  select id into cid from public.conversations
   where kind = 'channel' and archived_at is null
     and lower(replace(replace(title, ' ', '-'), 'ė', 'e')) in ('sandelio-raktas', '#sandelio-raktas')
   order by created_at limit 1;
  if cid is null then
    insert into public.conversations (kind, title, topic, is_private, created_by)
    values ('channel', 'sandėlio-raktas', 'Sandėlio spynos kodai (iš Ofisas → Raktai)', true, auth.uid()) returning id into cid;
  end if;
  insert into public.conversation_members (conversation_id, user_id)
  select cid, p.id from public.profiles p
   where (p.id = auth.uid() or public.keys_viewer(p.id)) and public.user_can_chat(p.id)
  on conflict do nothing;
  ts := to_char(k.applied_at at time zone 'Europe/Vilnius', 'YYYY-MM-DD HH24:MI');
  insert into public.messages (conversation_id, sender_id, body)
  values (cid, auth.uid(), '🔑 Naujas sandėlio rakto kodas: ' || k.code || E'\nKodas ant spynos pakeistas ' || ts || coalesce(' (' || who || ')', '') || '.');
  return cid;
end $$;
grant execute on function public.key_code_applied(uuid) to authenticated;

notify pgrst, 'reload schema';
