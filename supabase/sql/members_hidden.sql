-- ============================================================
-- Paslėpti nariai (Admin → Nariai, tik Super Admin): profiles.hidden = true –
-- narys niekur nerodomas (narių sąrašai, pasirinkimai, chatas, Admin), jį mato tik Super Admin.
-- Prisijungti ir dirbti jis gali kaip anksčiau. Saugu paleisti pakartotinai.
-- ============================================================
alter table public.profiles add column if not exists hidden boolean not null default false;

-- only the Super Admin hides / shows a member (nobody hides or unhides themselves)
create or replace function public.profiles_hidden_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if new.hidden is distinct from old.hidden and auth.uid() is not null and not coalesce(public.is_super(), false) then
    new.hidden := old.hidden;
  end if;
  return new;
end $$;
drop trigger if exists profiles_hidden_guard on public.profiles;
create trigger profiles_hidden_guard before update on public.profiles
  for each row execute function public.profiles_hidden_guard();

create or replace function public.member_set_hidden(uid uuid, on_off boolean) returns boolean
  language plpgsql security definer set search_path = public as $$
begin
  if not coalesce(public.is_super(), false) then raise exception 'Tik Super Admin'; end if;
  update public.profiles set hidden = on_off where id = uid;
  return found;
end $$;
revoke all on function public.member_set_hidden(uuid, boolean) from public, anon;
grant execute on function public.member_set_hidden(uuid, boolean) to authenticated;

notify pgrst, 'reload schema';
select 'members_hidden ok' as result, count(*) filter (where hidden) as hidden from public.profiles;
