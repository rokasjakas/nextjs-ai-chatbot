-- ============================================================
-- Chate — bet kokie failai iki 200 MB (PDF, Excel, video, ZIP…).
-- Paleisti PO notifications.sql. Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
--
-- SVARBU: Supabase turi ir bendrą viso projekto failo dydžio ribą:
-- Storage → Settings → „Upload file size limit“. Nemokamame plane ji
-- ne didesnė nei 50 MB; 200 MB leidžia tik Pro planas.
-- ============================================================
update storage.buckets
   set file_size_limit = 209715200,          -- 200 MB
       allowed_mime_types = null             -- bet koks failo tipas
 where id = 'chat-files';

-- pokalbių sąraše: ar paskutinė žinutė buvo failas, ar nuotrauka
drop function if exists public.chat_overview();
create function public.chat_overview() returns table (
  id uuid, kind text, title text, last_message_at timestamptz, members uuid[],
  last_body text, last_sender uuid, last_attachments int, unread int, created_by uuid, last_att_kind text)
  language sql stable security definer set search_path = public as $$
  select c.id, c.kind, c.title, c.last_message_at,
         coalesce((select array_agg(m.user_id) from public.conversation_members m where m.conversation_id = c.id), '{}'),
         lm.body, lm.sender_id, coalesce(jsonb_array_length(lm.attachments), 0),
         (select count(*)::int from public.messages x
           where x.conversation_id = c.id and x.deleted_at is null and x.sender_id <> auth.uid()
             and x.created_at > coalesce((select m.last_read_at from public.conversation_members m
                                          where m.conversation_id = c.id and m.user_id = auth.uid()), now() - interval '7 days')),
         c.created_by,
         lm.attachments -> 0 ->> 'type'
  from public.conversations c
  left join lateral (select body, sender_id, attachments from public.messages x
                      where x.conversation_id = c.id and x.deleted_at is null
                      order by x.created_at desc limit 1) lm on true
  where public.is_conv_member(c.id)
  order by (c.kind = 'general') desc, c.last_message_at desc
$$;
grant execute on function public.chat_overview() to authenticated;
