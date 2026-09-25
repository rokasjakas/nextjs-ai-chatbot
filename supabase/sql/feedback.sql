-- Klaidos / pasiūlymai: anyone signed in reports a bug or suggests an idea;
-- only admins see all of them and mark them fixed / accepted / rejected.
-- The author sees their own and is told when one is resolved.

create table if not exists public.feedback (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  created_by  uuid not null default auth.uid() references auth.users(id) on delete cascade,
  kind        text not null check (kind in ('bug', 'idea')),
  text        text not null check (length(text) between 1 and 5000),
  page        text,
  meta        jsonb not null default '{}'::jsonb,     -- app version, device, recent errors
  images      jsonb not null default '[]'::jsonb,     -- small compressed screenshots (data URLs)
  status      text not null default 'new' check (status in ('new', 'progress', 'fixed', 'accepted', 'rejected')),
  admin_note  text,
  resolved_at timestamptz,
  resolved_by uuid references auth.users(id) on delete set null,
  author_seen boolean not null default true           -- false = the author has not yet seen the answer
);
create index if not exists feedback_created_by_idx on public.feedback (created_by);
create index if not exists feedback_status_idx on public.feedback (status);

alter table public.feedback enable row level security;

drop policy if exists "feedback insert" on public.feedback;
create policy "feedback insert" on public.feedback
  for insert to authenticated with check (
    created_by = auth.uid() and public.is_approved()
    and status = 'new' and admin_note is null and resolved_at is null and resolved_by is null and author_seen
    and pg_column_size(images) < 1500000
  );

drop policy if exists "feedback read" on public.feedback;
create policy "feedback read" on public.feedback
  for select to authenticated using (created_by = auth.uid() or public.is_admin());

drop policy if exists "feedback admin update" on public.feedback;
create policy "feedback admin update" on public.feedback
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "feedback admin delete" on public.feedback;
create policy "feedback admin delete" on public.feedback
  for delete to authenticated using (public.is_admin());

grant select, insert, update, delete on public.feedback to authenticated;

-- the author marks the answers as seen (they may not change anything else)
create or replace function public.feedback_seen(ids uuid[])
returns void language sql security definer set search_path = public as $$
  update public.feedback set author_seen = true
   where id = any(ids) and created_by = auth.uid();
$$;
revoke all on function public.feedback_seen(uuid[]) from public;
grant execute on function public.feedback_seen(uuid[]) to authenticated;

do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'feedback') then
    execute 'alter publication supabase_realtime add table public.feedback';
  end if;
end $$;
