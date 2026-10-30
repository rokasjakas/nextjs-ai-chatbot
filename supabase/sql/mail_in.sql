-- ============================================================
-- El. paštas: persiųsti laiškai atsidaro iš karto (net dideli)
--  * pašto serveris kiekvieną naują laišką persiunčia į <vardas>@esmail.lt
--  * Cloudflare Email Routing → Email Worker (cloudflare/mail-in-worker.js) → „mail-in“ funkcija
--  * mail_in – laiško turinys, siuntėjas, gavėjai, priedų sąrašas
--  * saugykla „mail-in“ – priedai (<narys>/<laiškas>/<failas>)
--  * kiekvienas mato TIK SAVO laiškus; rašo tik „mail-in“ funkcija; laikoma 120 d.
-- Reikia: mail.sql. Funkcija: supabase functions deploy mail-in --no-verify-jwt
--         ir slaptas raktas: supabase secrets set MAIL_IN_SECRET=<ilgas atsitiktinis tekstas>
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.mail_in (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users(id) on delete cascade,
  message_id  text,
  date        timestamptz,
  subject     text not null default '',
  from_addr   jsonb not null default '[]'::jsonb,
  to_addr     jsonb not null default '[]'::jsonb,
  cc_addr     jsonb not null default '[]'::jsonb,
  reply_to    jsonb not null default '[]'::jsonb,
  refs        jsonb not null default '[]'::jsonb,
  html        text not null default '',
  text        text not null default '',
  attachments jsonb not null default '[]'::jsonb,
  size        integer,
  created_at  timestamptz not null default now()
);
create index if not exists mail_in_find on public.mail_in (user_id, date desc);
create index if not exists mail_in_msgid on public.mail_in (user_id, message_id);

alter table public.mail_in enable row level security;
drop policy if exists "own forwarded mail" on public.mail_in;
create policy "own forwarded mail" on public.mail_in for select to authenticated using (user_id = auth.uid());
revoke all on public.mail_in from anon;
revoke insert, update, delete on public.mail_in from authenticated;
grant select on public.mail_in to authenticated;

-- attachments: private, each member reads only their own folder
insert into storage.buckets (id, name, public, file_size_limit) values ('mail-in', 'mail-in', false, 52428800)
on conflict (id) do update set public = false;
drop policy if exists "own forwarded mail files" on storage.objects;
create policy "own forwarded mail files" on storage.objects for select to authenticated
  using (bucket_id = 'mail-in' and (storage.foldername(name))[1] = auth.uid()::text);

-- signed out of mail: the forwarded letters go too
create or replace function public.mail_in_cleanup() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  delete from public.mail_in where user_id = old.user_id;
  return old;
end $$;
drop trigger if exists mail_in_cleanup on public.mail_accounts;
create trigger mail_in_cleanup after delete on public.mail_accounts for each row execute function public.mail_in_cleanup();

notify pgrst, 'reload schema';
