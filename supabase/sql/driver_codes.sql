-- Vairuotojų kodai (UTA): kiekvienam renginyje priskirtam vairuotojui – unikalus 4 skaitmenų kodas
-- (pagal vardą pavardę; tas pats žmogus visada gauna tą patį kodą, nesvarbu, darbuotojas ar ne).
-- Kodą vairuotojas įrašo pildydamas kuro išlaidą ar žymėdamas kuro pylimą prie transporto.
-- Antras pylimas ta pačia UTA kortele per 1 val. paaiškinamas (uta_tx_notes).

create table if not exists public.driver_codes (
  key text primary key,                       -- vardas pavardė, normalizuota (mažosios, be lietuviškų raidžių)
  name text not null,
  code text not null unique check (code ~ '^[0-9]{4}$'),
  created_at timestamptz not null default now(),
  created_by uuid default auth.uid()
);
alter table public.driver_codes enable row level security;
drop policy if exists "driver codes view" on public.driver_codes;
create policy "driver codes view" on public.driver_codes for select to authenticated
  using (coalesce(public.my_role(), '') not in ('', 'pending', 'blocked'));
grant select on public.driver_codes to authenticated;

-- p: [{ "k": "jonas jonaitis", "n": "Jonas Jonaitis" }, …] → visų jų kodai (trūkstami sukuriami)
create or replace function public.driver_codes_ensure(p jsonb)
returns setof public.driver_codes
language plpgsql security definer set search_path = public as $$
declare x jsonb; k text; c text; n int;
begin
  if coalesce(public.my_role(), '') in ('', 'pending', 'blocked') then raise exception 'not allowed'; end if;
  for x in select * from jsonb_array_elements(coalesce(p, '[]'::jsonb)) loop
    k := lower(trim(x->>'k'));
    if k is null or k = '' or length(k) > 120 then continue; end if;
    if exists (select 1 from public.driver_codes where key = k) then continue; end if;
    n := 0;
    loop
      n := n + 1;
      c := lpad((1000 + floor(random() * 9000))::int::text, 4, '0');
      begin
        insert into public.driver_codes(key, name, code) values (k, left(trim(coalesce(x->>'n', k)), 120), c);
        exit;
      exception when unique_violation then
        if exists (select 1 from public.driver_codes where key = k) then exit; end if;   -- kitas ką tik sukūrė
        if n > 200 then raise exception 'no free code'; end if;
      end;
    end loop;
  end loop;
  return query select d.* from public.driver_codes d
    where d.key in (select lower(trim(e->>'k')) from jsonb_array_elements(coalesce(p, '[]'::jsonb)) e);
end $$;
revoke all on function public.driver_codes_ensure(jsonb) from public, anon;
grant execute on function public.driver_codes_ensure(jsonb) to authenticated;

-- kas pylė: kodas prie kuro išlaidos
alter table public.expenses add column if not exists driver_code text;

-- pylimo paaiškinimas (pvz. antras pylimas ta pačia kortele per 1 val.: kitas transportas, bakelis…)
create table if not exists public.uta_tx_notes (
  tx_id uuid primary key references public.uta_tx(id) on delete cascade,
  kind text not null check (kind in ('card', 'other', 'rent', 'can', 'misc')),
  plate text,
  note text,
  by_id uuid default auth.uid(),
  by_name text,
  updated_at timestamptz not null default now()
);
alter table public.uta_tx_notes enable row level security;
drop policy if exists "uta notes view" on public.uta_tx_notes;
create policy "uta notes view" on public.uta_tx_notes for select to authenticated using (public.can_view('fleet') or public.can_view('stats'));
drop policy if exists "uta notes edit" on public.uta_tx_notes;
create policy "uta notes edit" on public.uta_tx_notes for all to authenticated using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
grant select, insert, update, delete on public.uta_tx_notes to authenticated;

-- QR puslapis (Kuro pylimas): kodo patikrinimas (p_log null) ir įrašymas prie ką tik užregistruoto pylimo
create or replace function public.vehicle_log_code(p_token text, p_log uuid, p_code text)
returns boolean language plpgsql security definer set search_path = public as $$
declare v jsonb; nm text;
begin
  v := public.vehicle_by_token(p_token);
  if v is null then raise exception 'QR kodas nebegalioja.'; end if;
  if coalesce(p_code, '') !~ '^[0-9]{4}$' then return false; end if;
  select name into nm from public.driver_codes where code = p_code;
  if nm is null then return false; end if;
  if p_log is not null then
    update public.vehicle_logs set data = coalesce(data, '{}'::jsonb) || jsonb_build_object('driver_code', p_code, 'driver_name', nm)
     where id = p_log and vehicle_id = v ->> 'id' and kind = 'fuel' and data ->> 'via' = 'qr' and created_at > now() - interval '15 minutes';
  end if;
  return true;
end $$;
revoke all on function public.vehicle_log_code(text, uuid, text) from public;
grant execute on function public.vehicle_log_code(text, uuid, text) to anon, authenticated;

notify pgrst, 'reload schema';
