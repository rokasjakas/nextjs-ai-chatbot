-- ============================================================
-- Kalendorius: susitikimai su žmonėmis iš išorės (svečiais)
--  * kiekvienas pakviestas el. paštu gauna asmeninę nuorodą (?svecias=<raktas>):
--    „Dalyvausiu / Nedalyvausiu“, susitikimo informacija, pridėti į kalendorių
--  * „Online susitikimas“: dar ir pokalbis (žinutės, failai, bendri užrašai) ir
--    vaizdo skambutis; nariai jį mato chate kaip grupę „🤝 <tema>“
--  * visiems išėjus iš skambučio jis baigiamas, visiems išsiunčiama santrauka
--    (užrašai, failai, žinutės)
--  * svečiai jungiasi tik per funkciją „guest“ (su raktu), tiesiai į duomenų bazę – ne
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.meetings add column if not exists online boolean not null default false;
alter table public.meetings add column if not exists conversation_id uuid references public.conversations(id) on delete set null;
alter table public.meetings add column if not exists notes text not null default '';
alter table public.meetings add column if not exists summary_sent_at timestamptz;

create table if not exists public.meeting_guests (
  id           uuid primary key default gen_random_uuid(),
  meeting_id   uuid not null references public.meetings(id) on delete cascade,
  email        text not null,
  name         text,
  token        text not null unique default (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  status       text not null default 'pending' check (status in ('pending','yes','no')),
  responded_at timestamptz,
  last_seen_at timestamptz,
  created_at   timestamptz not null default now(),
  unique (meeting_id, email)
);
create index if not exists meeting_guests_meeting on public.meeting_guests (meeting_id);
alter table public.meeting_guests enable row level security;
-- the organizer and the invited members see who answered (and the organizer can copy the links)
drop policy if exists "meeting guests view" on public.meeting_guests;
create policy "meeting guests view" on public.meeting_guests for select to authenticated using (
  exists (select 1 from public.meetings m where m.id = meeting_id and (m.created_by = auth.uid() or auth.uid() = any (m.attendees))));
revoke all on public.meeting_guests from anon, authenticated;
grant select on public.meeting_guests to authenticated;

-- the organizer and the invited members may write the shared notes
drop policy if exists "meeting notes by attendees" on public.meetings;
create or replace function public.meeting_set_notes(p_id uuid, p_notes text) returns void
  language plpgsql security definer set search_path = public as $$
begin
  update public.meetings set notes = left(coalesce(p_notes, ''), 20000), updated_at = now()
   where id = p_id and (created_by = auth.uid() or auth.uid() = any (attendees));
end $$;
revoke all on function public.meeting_set_notes(uuid, text) from public, anon;
grant execute on function public.meeting_set_notes(uuid, text) to authenticated;

-- a guest's message: kept with the organizer as sender (the table needs a member),
-- the guest's name shown instead
alter table public.messages add column if not exists guest_id uuid references public.meeting_guests(id) on delete set null;
alter table public.messages add column if not exists guest_name text;

-- live answers for the organizer's screen
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'meeting_guests') then
    execute 'alter publication supabase_realtime add table public.meeting_guests';
  end if;
end $$;

-- ---------- pokalbių sąrašas: svečių žinutės neperskaitytos ir organizatoriui ----------
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
           where x.conversation_id = c.id and x.deleted_at is null and (x.sender_id <> auth.uid() or x.guest_id is not null)
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
