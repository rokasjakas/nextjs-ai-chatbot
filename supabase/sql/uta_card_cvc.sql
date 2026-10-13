-- ============================================================
-- UTA kortelės CVC (3 skaičiai kortelės gale) – „Kuro kortelė“ renginio laiške: vairuotojas įrašo
-- paskutinius 5 kortelės skaitmenis ir CVC, funkcija „uta-pin“ juos patikrina ir parodo PIN.
-- CVC mato ir keičia tik redaguojantys „Transportą“ (Transportas → UTA kortelės → kortelė);
-- funkcija jį skaito su service role. Reikia: uta.sql. Saugu paleisti pakartotinai.
-- ============================================================
create table if not exists public.uta_card_cvc (
  card_id    uuid primary key references public.uta_cards(id) on delete cascade,
  cvc        text not null check (cvc ~ '^[0-9]{3,4}$'),
  updated_by uuid default auth.uid(),
  updated_at timestamptz not null default now()
);
alter table public.uta_card_cvc enable row level security;
drop policy if exists "uta cvc edit" on public.uta_card_cvc;
create policy "uta cvc edit" on public.uta_card_cvc for all to authenticated
  using (public.can_edit('fleet')) with check (public.can_edit('fleet'));
revoke all on public.uta_card_cvc from anon;
grant select, insert, update, delete on public.uta_card_cvc to authenticated;
notify pgrst, 'reload schema';
