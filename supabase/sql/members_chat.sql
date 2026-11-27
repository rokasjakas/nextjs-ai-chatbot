-- ============================================================
-- Nariai ir žinutės: profilis (vardas, slapyvardis, telefonas, nuotrauka),
-- matomumas kitiems komandos nariams, bendras chatas, asmeninės ir grupinės
-- žinutės su nuotraukomis / GIF.
-- Paleisti PO user_roles.sql (ir iš naujo, jei user_roles.sql buvo paleistas
-- dar kartą). Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- profilis ----------
alter table public.profiles add column if not exists first_name    text;
alter table public.profiles add column if not exists last_name     text;
alter table public.profiles add column if not exists nickname      text;
alter table public.profiles add column if not exists phone         text;
alter table public.profiles add column if not exists contact_email text;
alter table public.profiles add column if not exists avatar_path   text;
alter table public.profiles add column if not exists last_seen     timestamptz;
alter table public.profiles add column if not exists profile_done  boolean not null default false;

-- Vartotojas gali keisti savo profilį, bet ne lygį / patvirtinimą / prisijungimo el. paštą.
create or replace function public.profiles_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if old.role = 'admin' and new.role <> 'admin'
     and not exists (select 1 from public.profiles where role = 'admin' and id <> old.id) then
    raise exception 'Negalima pašalinti paskutinio administratoriaus.';
  end if;
  -- auth.uid() is null: Supabase SQL Editor or server functions (service role)
  if auth.uid() is not null and not public.is_admin() then
    if new.id is distinct from old.id or new.role is distinct from old.role
       or new.email is distinct from old.email or new.approved_at is distinct from old.approved_at
       or new.approved_by is distinct from old.approved_by or new.notified_at is distinct from old.notified_at then
      raise exception 'Šių profilio laukų keisti negalima.';
    end if;
  end if;
  if new.role <> old.role and old.role = 'pending' and new.role not in ('pending','blocked') then
    new.approved_at := now();
    new.approved_by := coalesce(auth.jwt() ->> 'email', new.approved_by);
  end if;
  return new;
end $$;

-- komandos nariai mato vieni kitus (laukiantys ir užblokuoti nematomi)
drop policy if exists "own profile or admin" on public.profiles;
drop policy if exists "team sees members" on public.profiles;
create policy "team sees members" on public.profiles
  for select to authenticated using (
    id = auth.uid() or public.is_admin()
    or (public.is_approved() and role in ('admin','pm','office','tech','freelance','runner'))
  );
drop policy if exists "own profile update" on public.profiles;
create policy "own profile update" on public.profiles
  for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

-- ---------- pokalbiai ----------
create table if not exists public.conversations (
  id              uuid primary key default gen_random_uuid(),
  kind            text not null check (kind in ('general','direct','group')),
  title           text,
  created_by      uuid references auth.users(id) on delete set null,
  created_at      timestamptz not null default now(),
  last_message_at timestamptz not null default now()
);
create unique index if not exists conversations_one_general on public.conversations (kind) where kind = 'general';

create table if not exists public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id         uuid not null references auth.users(id) on delete cascade,
  joined_at       timestamptz not null default now(),
  last_read_at    timestamptz not null default now(),
  primary key (conversation_id, user_id)
);
create index if not exists conversation_members_user_idx on public.conversation_members (user_id);

create table if not exists public.messages (
  id              uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id       uuid not null default auth.uid() references auth.users(id) on delete cascade,
  body            text not null default '',
  attachments     jsonb not null default '[]',
  created_at      timestamptz not null default now(),
  deleted_at      timestamptz
);
create index if not exists messages_conv_created_idx on public.messages (conversation_id, created_at desc);

-- bendras chatas visai komandai
insert into public.conversations (kind, title) values ('general', 'Bendras chatas')
on conflict do nothing;

-- ar vartotojas mato pokalbį
create or replace function public.is_conv_member(cid uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select public.is_approved() and (
    exists (select 1 from public.conversations c where c.id = cid and c.kind = 'general')
    or exists (select 1 from public.conversation_members m where m.conversation_id = cid and m.user_id = auth.uid())
  )
$$;

alter table public.conversations        enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages             enable row level security;

drop policy if exists "see own conversations" on public.conversations;
create policy "see own conversations" on public.conversations
  for select to authenticated using (public.is_conv_member(id));
drop policy if exists "rename own group" on public.conversations;
create policy "rename own group" on public.conversations
  for update to authenticated using (kind = 'group' and public.is_conv_member(id)) with check (kind = 'group');

drop policy if exists "see members of own conversations" on public.conversation_members;
create policy "see members of own conversations" on public.conversation_members
  for select to authenticated using (public.is_conv_member(conversation_id));
drop policy if exists "mark own read" on public.conversation_members;
create policy "mark own read" on public.conversation_members
  for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
drop policy if exists "join general" on public.conversation_members;
create policy "join general" on public.conversation_members
  for insert to authenticated with check (
    user_id = auth.uid() and public.is_approved()
    and exists (select 1 from public.conversations c where c.id = conversation_id and c.kind = 'general'));
drop policy if exists "leave conversation" on public.conversation_members;
create policy "leave conversation" on public.conversation_members
  for delete to authenticated using (user_id = auth.uid());

drop policy if exists "read messages" on public.messages;
create policy "read messages" on public.messages
  for select to authenticated using (public.is_conv_member(conversation_id));
drop policy if exists "send messages" on public.messages;
create policy "send messages" on public.messages
  for insert to authenticated with check (sender_id = auth.uid() and public.is_conv_member(conversation_id));
drop policy if exists "delete own messages" on public.messages;
create policy "delete own messages" on public.messages
  for update to authenticated using (sender_id = auth.uid()) with check (sender_id = auth.uid());

-- naujausia žinutė pakelia pokalbį sąrašo viršuje
create or replace function public.messages_touch_conv() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  update public.conversations set last_message_at = new.created_at where id = new.conversation_id;
  return new;
end $$;
drop trigger if exists messages_touch_conv on public.messages;
create trigger messages_touch_conv after insert on public.messages
  for each row execute function public.messages_touch_conv();

-- asmeninis pokalbis su kitu nariu (sukuriamas, jei dar nėra)
create or replace function public.chat_direct(other uuid) returns uuid
  language plpgsql security definer set search_path = public as $$
declare cid uuid;
begin
  if not public.is_approved() then raise exception 'Nėra prieigos.'; end if;
  if other = auth.uid() then raise exception 'Negalima rašyti sau.'; end if;
  if not exists (select 1 from public.profiles where id = other and role in ('admin','pm','office','tech','freelance','runner')) then
    raise exception 'Narys nerastas.';
  end if;
  select c.id into cid from public.conversations c
   where c.kind = 'direct'
     and exists (select 1 from public.conversation_members m where m.conversation_id = c.id and m.user_id = auth.uid())
     and exists (select 1 from public.conversation_members m where m.conversation_id = c.id and m.user_id = other)
   limit 1;
  if cid is null then
    insert into public.conversations (kind, created_by) values ('direct', auth.uid()) returning id into cid;
    insert into public.conversation_members (conversation_id, user_id) values (cid, auth.uid()), (cid, other);
  end if;
  return cid;
end $$;

-- grupė
create or replace function public.chat_group(title text, member_ids uuid[]) returns uuid
  language plpgsql security definer set search_path = public as $$
declare cid uuid;
begin
  if not public.is_approved() then raise exception 'Nėra prieigos.'; end if;
  insert into public.conversations (kind, title, created_by) values ('group', nullif(trim(title), ''), auth.uid()) returning id into cid;
  insert into public.conversation_members (conversation_id, user_id)
  select cid, p.id from public.profiles p
   where (p.id = auth.uid() or p.id = any(member_ids)) and p.role in ('admin','pm','office','tech','freelance','runner')
  on conflict do nothing;
  return cid;
end $$;

-- pridėti narių į grupę (gali bet kuris grupės narys)
create or replace function public.chat_group_add(cid uuid, member_ids uuid[]) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.conversations where id = cid and kind = 'group') or not public.is_conv_member(cid) then
    raise exception 'Nėra prieigos.';
  end if;
  insert into public.conversation_members (conversation_id, user_id)
  select cid, p.id from public.profiles p
   where p.id = any(member_ids) and p.role in ('admin','pm','office','tech','freelance','runner')
  on conflict do nothing;
end $$;

-- pokalbių sąrašas: paskutinė žinutė, neperskaitytų skaičius, nariai
create or replace function public.chat_overview() returns table (
  id uuid, kind text, title text, last_message_at timestamptz, members uuid[],
  last_body text, last_sender uuid, last_attachments int, unread int)
  language sql stable security definer set search_path = public as $$
  select c.id, c.kind, c.title, c.last_message_at,
         coalesce((select array_agg(m.user_id) from public.conversation_members m where m.conversation_id = c.id), '{}'),
         lm.body, lm.sender_id, coalesce(jsonb_array_length(lm.attachments), 0),
         (select count(*)::int from public.messages x
           where x.conversation_id = c.id and x.deleted_at is null and x.sender_id <> auth.uid()
             and x.created_at > coalesce((select m.last_read_at from public.conversation_members m
                                          where m.conversation_id = c.id and m.user_id = auth.uid()), now() - interval '7 days'))
  from public.conversations c
  left join lateral (select body, sender_id, attachments from public.messages x
                      where x.conversation_id = c.id and x.deleted_at is null
                      order by x.created_at desc limit 1) lm on true
  where public.is_conv_member(c.id)
  order by (c.kind = 'general') desc, c.last_message_at desc
$$;

-- pažymėti perskaitytu
create or replace function public.chat_read(cid uuid) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not public.is_conv_member(cid) then return; end if;
  insert into public.conversation_members (conversation_id, user_id, last_read_at) values (cid, auth.uid(), now())
  on conflict (conversation_id, user_id) do update set last_read_at = now();
end $$;

grant execute on function public.is_conv_member(uuid), public.chat_direct(uuid), public.chat_group(text, uuid[]),
  public.chat_group_add(uuid, uuid[]), public.chat_overview(), public.chat_read(uuid) to authenticated;

-- žinutės realiu laiku
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages') then
    execute 'alter publication supabase_realtime add table public.messages';
  end if;
end $$;

-- ---------- nuotraukos: profilio ir pokalbių ----------
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', false) on conflict (id) do nothing;
insert into storage.buckets (id, name, public) values ('chat-files', 'chat-files', false) on conflict (id) do nothing;

drop policy if exists "avatars view" on storage.objects;
create policy "avatars view" on storage.objects
  for select to authenticated using (bucket_id = 'avatars' and public.is_approved());
drop policy if exists "avatars own" on storage.objects;
create policy "avatars own" on storage.objects
  for insert to authenticated with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "avatars own change" on storage.objects;
create policy "avatars own change" on storage.objects
  for update to authenticated using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "avatars own delete" on storage.objects;
create policy "avatars own delete" on storage.objects
  for delete to authenticated using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "chat files view" on storage.objects;
create policy "chat files view" on storage.objects
  for select to authenticated using (bucket_id = 'chat-files' and public.is_conv_member(((storage.foldername(name))[1])::uuid));
drop policy if exists "chat files add" on storage.objects;
create policy "chat files add" on storage.objects
  for insert to authenticated with check (bucket_id = 'chat-files' and public.is_conv_member(((storage.foldername(name))[1])::uuid));
