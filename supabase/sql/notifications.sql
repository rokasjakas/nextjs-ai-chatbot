-- ============================================================
-- Pranešimai (telefone ir kompiuteryje) ir grupių trynimas.
--  * profiles.notify_prefs — ką pranešti, nutildyti pokalbiai, tylos valandos
--  * push_subscriptions    — įrenginiai, kuriuose įjungti pranešimai
--  * chat_group_delete     — grupę ištrina jos kūrėjas arba Admin
-- Paleisti PO chat_access.sql. Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

alter table public.profiles add column if not exists notify_prefs jsonb not null default '{}'::jsonb;

create table if not exists public.push_subscriptions (
  endpoint   text primary key,
  user_id    uuid not null references auth.users(id) on delete cascade,
  p256dh     text not null,
  auth       text not null,
  user_agent text,
  created_at timestamptz not null default now()
);
create index if not exists push_subscriptions_user_idx on public.push_subscriptions (user_id);

alter table public.push_subscriptions enable row level security;
drop policy if exists "own devices" on public.push_subscriptions;
create policy "own devices" on public.push_subscriptions
  for select to authenticated using (user_id = auth.uid());
drop policy if exists "remove own device" on public.push_subscriptions;
create policy "remove own device" on public.push_subscriptions
  for delete to authenticated using (user_id = auth.uid());

-- įrenginio registracija (tas pats įrenginys galėjo būti kito nario — perrašoma)
create or replace function public.push_register(p_endpoint text, p_p256dh text, p_auth text, p_ua text) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not public.is_approved() then raise exception 'Nėra prieigos.'; end if;
  if p_endpoint !~ '^https://' then raise exception 'Netinkamas adresas.'; end if;
  insert into public.push_subscriptions (endpoint, user_id, p256dh, auth, user_agent)
  values (p_endpoint, auth.uid(), p_p256dh, p_auth, left(p_ua, 300))
  on conflict (endpoint) do update set user_id = auth.uid(), p256dh = excluded.p256dh, auth = excluded.auth,
                                       user_agent = excluded.user_agent, created_at = now();
end $$;
grant execute on function public.push_register(text, text, text, text) to authenticated;

-- grupės kūrėjas ir pokalbių sąraše
drop function if exists public.chat_overview();
create function public.chat_overview() returns table (
  id uuid, kind text, title text, last_message_at timestamptz, members uuid[],
  last_body text, last_sender uuid, last_attachments int, unread int, created_by uuid)
  language sql stable security definer set search_path = public as $$
  select c.id, c.kind, c.title, c.last_message_at,
         coalesce((select array_agg(m.user_id) from public.conversation_members m where m.conversation_id = c.id), '{}'),
         lm.body, lm.sender_id, coalesce(jsonb_array_length(lm.attachments), 0),
         (select count(*)::int from public.messages x
           where x.conversation_id = c.id and x.deleted_at is null and x.sender_id <> auth.uid()
             and x.created_at > coalesce((select m.last_read_at from public.conversation_members m
                                          where m.conversation_id = c.id and m.user_id = auth.uid()), now() - interval '7 days')),
         c.created_by
  from public.conversations c
  left join lateral (select body, sender_id, attachments from public.messages x
                      where x.conversation_id = c.id and x.deleted_at is null
                      order by x.created_at desc limit 1) lm on true
  where public.is_conv_member(c.id)
  order by (c.kind = 'general') desc, c.last_message_at desc
$$;
grant execute on function public.chat_overview() to authenticated;

-- ištrinti grupę (su visomis žinutėmis) gali jos kūrėjas arba Admin
create or replace function public.chat_group_delete(cid uuid) returns void
  language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.conversations c where c.id = cid and c.kind = 'group'
                 and (c.created_by = auth.uid() or public.is_admin())) then
    raise exception 'Ištrinti gali tik grupės kūrėjas arba administratorius.';
  end if;
  delete from public.conversations where id = cid;
end $$;
grant execute on function public.chat_group_delete(uuid) to authenticated;

-- ištrintos grupės nuotraukas gali pašalinti jos kūrėjas arba Admin
drop policy if exists "chat files delete by owner" on storage.objects;
create policy "chat files delete by owner" on storage.objects
  for delete to authenticated using (
    bucket_id = 'chat-files' and exists (
      select 1 from public.conversations c
      where c.id::text = (storage.foldername(name))[1] and (c.created_by = auth.uid() or public.is_admin())));
