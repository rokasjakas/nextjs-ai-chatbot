-- ============================================================
-- Chatas kaip Slack:
--  * kanalai: vieši (# — mato ir gali prisijungti visi) ir privatūs (🔒)
--  * gijos (atsakymai į žinutę), „taip pat siųsti į kanalą“
--  * žinučių redagavimas, @paminėjimai (<@id> tekste)
--  * „Vėliau“ — išsaugotos žinutės
--  * Veikla (paminėjimai, atsakymai gijose, reakcijos) ir Failai
-- Paleisti PO chat_files.sql. Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- kanalai ----------
alter table public.conversations drop constraint if exists conversations_kind_check;
alter table public.conversations add constraint conversations_kind_check
  check (kind in ('general','direct','group','channel'));
alter table public.conversations add column if not exists topic       text not null default '';
alter table public.conversations add column if not exists is_private  boolean not null default true;
alter table public.conversations add column if not exists archived_at timestamptz;
update public.conversations set is_private = false where kind = 'general' and is_private;

-- viešus kanalus mato visi, kas naudojasi chatu
create or replace function public.is_conv_member(cid uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select public.is_approved() and public.user_can_chat(auth.uid()) and (
    exists (select 1 from public.conversations c where c.id = cid and (c.kind = 'general' or (c.kind = 'channel' and not c.is_private)))
    or exists (select 1 from public.conversation_members m where m.conversation_id = cid and m.user_id = auth.uid())
  )
$$;

drop policy if exists "join general" on public.conversation_members;
drop policy if exists "join public channels" on public.conversation_members;
create policy "join public channels" on public.conversation_members
  for insert to authenticated with check (
    user_id = auth.uid() and public.is_approved() and public.user_can_chat(auth.uid())
    and exists (select 1 from public.conversations c where c.id = conversation_id
                and (c.kind = 'general' or (c.kind = 'channel' and not c.is_private))));

drop policy if exists "rename own group" on public.conversations;
drop policy if exists "edit channel" on public.conversations;
create policy "edit channel" on public.conversations
  for update to authenticated using (kind in ('group','channel') and public.is_conv_member(id))
  with check (kind in ('group','channel'));

-- ---------- gijos ir redagavimas ----------
alter table public.messages add column if not exists parent_id    uuid references public.messages(id) on delete cascade;
alter table public.messages add column if not exists also_channel boolean not null default false;
alter table public.messages add column if not exists edited_at    timestamptz;
create index if not exists messages_parent_idx on public.messages (parent_id) where parent_id is not null;

-- atsakymas gijoje pokalbio sąraše į viršų nekelia (nebent „taip pat į kanalą“)
create or replace function public.messages_touch_conv() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if new.parent_id is null or new.also_channel then
    update public.conversations set last_message_at = new.created_at where id = new.conversation_id;
  end if;
  return new;
end $$;

-- ---------- „Vėliau“ ----------
create table if not exists public.message_saves (
  user_id    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  message_id uuid not null references public.messages(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, message_id)
);
alter table public.message_saves enable row level security;
drop policy if exists "own saves" on public.message_saves;
create policy "own saves" on public.message_saves
  for select to authenticated using (user_id = auth.uid());
drop policy if exists "add own save" on public.message_saves;
create policy "add own save" on public.message_saves
  for insert to authenticated with check (user_id = auth.uid() and public.can_see_message(message_id));
drop policy if exists "remove own save" on public.message_saves;
create policy "remove own save" on public.message_saves
  for delete to authenticated using (user_id = auth.uid());

-- ---------- kanalų valdymas ----------
create or replace function public.chat_channel_create(p_name text, p_topic text, p_private boolean, member_ids uuid[])
  returns uuid language plpgsql security definer set search_path = public as $$
declare cid uuid; nm text := lower(regexp_replace(trim(coalesce(p_name,'')), '\s+', '-', 'g'));
begin
  if not public.is_approved() or not public.user_can_chat(auth.uid()) then raise exception 'Nėra prieigos prie chato.'; end if;
  if nm = '' then raise exception 'Įrašyk kanalo pavadinimą.'; end if;
  if exists (select 1 from public.conversations where kind in ('channel','group') and lower(title) = nm and archived_at is null) then
    raise exception 'Kanalas „%“ jau yra.', nm;
  end if;
  insert into public.conversations (kind, title, topic, is_private, created_by)
  values ('channel', nm, coalesce(p_topic,''), coalesce(p_private,false), auth.uid()) returning id into cid;
  insert into public.conversation_members (conversation_id, user_id)
  select cid, p.id from public.profiles p
   where (p.id = auth.uid() or p.id = any(coalesce(member_ids,'{}'))) and public.user_can_chat(p.id)
  on conflict do nothing;
  return cid;
end $$;
grant execute on function public.chat_channel_create(text, text, boolean, uuid[]) to authenticated;

-- nariai pridedami ir į kanalus
create or replace function public.chat_group_add(cid uuid, member_ids uuid[]) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.conversations where id = cid and kind in ('group','channel')) or not public.is_conv_member(cid) then
    raise exception 'Nėra prieigos.';
  end if;
  insert into public.conversation_members (conversation_id, user_id)
  select cid, p.id from public.profiles p
   where p.id = any(member_ids) and public.user_can_chat(p.id)
  on conflict do nothing;
end $$;

-- archyvuoti / grąžinti — kūrėjas arba Admin
create or replace function public.chat_channel_archive(cid uuid, p_archive boolean) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.conversations c where c.id = cid and c.kind in ('group','channel')
                 and (c.created_by = auth.uid() or public.is_admin())) then
    raise exception 'Archyvuoti gali tik kanalo kūrėjas arba administratorius.';
  end if;
  update public.conversations set archived_at = case when p_archive then now() else null end where id = cid;
end $$;
grant execute on function public.chat_channel_archive(uuid, boolean) to authenticated;

-- ištrinti — kūrėjas arba Admin (ir kanalams)
create or replace function public.chat_group_delete(cid uuid) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.conversations c where c.id = cid and c.kind in ('group','channel')
                 and (c.created_by = auth.uid() or public.is_admin())) then
    raise exception 'Ištrinti gali tik kanalo kūrėjas arba administratorius.';
  end if;
  delete from public.conversations where id = cid;
end $$;

-- visi kanalai naršymui
create or replace function public.chat_channels_browse() returns table (
  id uuid, kind text, title text, topic text, is_private boolean, archived_at timestamptz,
  created_by uuid, members int, joined boolean, last_message_at timestamptz)
  language sql stable security definer set search_path = public as $$
  select c.id, c.kind, c.title, c.topic, c.is_private, c.archived_at, c.created_by,
         (select count(*)::int from public.conversation_members m where m.conversation_id = c.id),
         c.kind = 'general' or exists (select 1 from public.conversation_members m where m.conversation_id = c.id and m.user_id = auth.uid()),
         c.last_message_at
  from public.conversations c
  where c.kind in ('general','channel','group') and public.is_conv_member(c.id)
  order by (c.kind = 'general') desc, c.title
$$;
grant execute on function public.chat_channels_browse() to authenticated;

-- ---------- pokalbių sąrašas ----------
drop function if exists public.chat_overview();
create function public.chat_overview() returns table (
  id uuid, kind text, title text, last_message_at timestamptz, members uuid[],
  last_body text, last_sender uuid, last_attachments int, unread int, created_by uuid, last_att_kind text,
  topic text, is_private boolean, archived_at timestamptz)
  language sql stable security definer set search_path = public as $$
  select c.id, c.kind, c.title, c.last_message_at,
         coalesce((select array_agg(m.user_id) from public.conversation_members m where m.conversation_id = c.id), '{}'),
         lm.body, lm.sender_id, coalesce(jsonb_array_length(lm.attachments), 0),
         (select count(*)::int from public.messages x
           where x.conversation_id = c.id and x.deleted_at is null and x.sender_id <> auth.uid()
             and (x.parent_id is null or x.also_channel)
             and x.created_at > coalesce((select m.last_read_at from public.conversation_members m
                                          where m.conversation_id = c.id and m.user_id = auth.uid()), now() - interval '7 days')),
         c.created_by,
         lm.attachments -> 0 ->> 'type',
         c.topic, c.is_private, c.archived_at
  from public.conversations c
  left join lateral (select body, sender_id, attachments from public.messages x
                      where x.conversation_id = c.id and x.deleted_at is null and (x.parent_id is null or x.also_channel)
                      order by x.created_at desc limit 1) lm on true
  where public.is_conv_member(c.id)
    and (c.kind = 'general' or exists (select 1 from public.conversation_members m where m.conversation_id = c.id and m.user_id = auth.uid()))
  order by (c.kind = 'general') desc, c.last_message_at desc
$$;
grant execute on function public.chat_overview() to authenticated;

-- ---------- Veikla: paminėjimai, atsakymai gijose, reakcijos ----------
create or replace function public.chat_activity(p_limit int default 80) returns table (
  kind text, message_id uuid, conversation_id uuid, parent_id uuid, actor uuid, body text, emoji text, created_at timestamptz)
  language sql stable security definer set search_path = public as $$
  select * from (
    select 'mention'::text, m.id, m.conversation_id, m.parent_id, m.sender_id, m.body, null::text, m.created_at
      from public.messages m
     where m.deleted_at is null and m.sender_id <> auth.uid()
       and m.body like '%<@' || auth.uid()::text || '>%'
       and public.is_conv_member(m.conversation_id)
    union all
    select 'thread', r.id, r.conversation_id, r.parent_id, r.sender_id, r.body, null, r.created_at
      from public.messages r
     where r.parent_id is not null and r.deleted_at is null and r.sender_id <> auth.uid()
       and r.body not like '%<@' || auth.uid()::text || '>%'
       and (exists (select 1 from public.messages p where p.id = r.parent_id and p.sender_id = auth.uid())
            or exists (select 1 from public.messages o where o.parent_id = r.parent_id and o.sender_id = auth.uid()))
       and public.is_conv_member(r.conversation_id)
    union all
    select 'reaction', m.id, m.conversation_id, m.parent_id, x.user_id, m.body, x.emoji, x.created_at
      from public.message_reactions x join public.messages m on m.id = x.message_id
     where m.sender_id = auth.uid() and x.user_id <> auth.uid() and m.deleted_at is null
  ) a
  order by 8 desc
  limit greatest(1, least(coalesce(p_limit, 80), 300))
$$;
grant execute on function public.chat_activity(int) to authenticated;

-- ---------- Failai ----------
drop function if exists public.chat_files(int);
create function public.chat_files(p_limit int default 300) returns table (
  message_id uuid, conversation_id uuid, parent_id uuid, also_channel boolean, sender_id uuid, attachments jsonb, body text, created_at timestamptz)
  language sql stable security definer set search_path = public as $$
  select m.id, m.conversation_id, m.parent_id, m.also_channel, m.sender_id, m.attachments, m.body, m.created_at
    from public.messages m
   where m.deleted_at is null and jsonb_array_length(m.attachments) > 0
     and public.is_conv_member(m.conversation_id)
   order by m.created_at desc
   limit greatest(1, least(coalesce(p_limit, 300), 1000))
$$;
grant execute on function public.chat_files(int) to authenticated;
