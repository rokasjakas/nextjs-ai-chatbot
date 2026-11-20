-- ============================================================
-- Chatas: prisegtos žinutės (📌) – visada rodomos pokalbio viršuje
--  * messages.pinned_at / pinned_by – kada ir kas prisegė
--  * chat_pin(p_mid, p_on) – prisegti / atsegti gali kiekvienas pokalbio narys
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.messages add column if not exists pinned_at timestamptz;
alter table public.messages add column if not exists pinned_by uuid references auth.users(id) on delete set null;
create index if not exists messages_pinned on public.messages (conversation_id, pinned_at) where pinned_at is not null;

create or replace function public.chat_pin(p_mid uuid, p_on boolean) returns jsonb
  language plpgsql security definer set search_path = public as $$
declare m public.messages;
begin
  select * into m from public.messages where id = p_mid;
  if m.id is null then return jsonb_build_object('error', 'Žinutės nėra.'); end if;
  if not public.is_conv_member(m.conversation_id) then return jsonb_build_object('error', 'Nesi šio pokalbio narys.'); end if;
  update public.messages set pinned_at = case when p_on then now() end, pinned_by = case when p_on then auth.uid() end
    where id = p_mid returning * into m;
  return to_jsonb(m);
end $$;
revoke all on function public.chat_pin(uuid, boolean) from public, anon;
grant execute on function public.chat_pin(uuid, boolean) to authenticated;

notify pgrst, 'reload schema';
