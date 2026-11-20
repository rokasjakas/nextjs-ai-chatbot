-- ============================================================
-- Sąskaitos: įkelti savo sąskaitą gali kiekvienas, kas mato „Sąskaitas“
-- (Tech, Freelance, Runner ir kt.), ir mato tik savo įkeltas bei jų būsenas.
-- Tvirtinti ir matyti visas – kaip anksčiau, tik Admin+.
-- Supabase → SQL Editor → New query → įklijuok → Run. Saugu paleisti pakartotinai.
-- ============================================================
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('tech','invoices',true,true), ('freelance','invoices',true,true), ('runner','invoices',true,true)
on conflict (role, section) do update set can_view = true, can_edit = true;

drop policy if exists "invoices add" on public.invoices;
create policy "invoices add" on public.invoices
  for insert to authenticated with check (
    created_by = auth.uid() and public.can_view('invoices')
    and status = 'new' and decision_by is null and decision_at is null and sent = '[]'::jsonb and responses = '[]'::jsonb
  );
drop policy if exists "invoice files add" on storage.objects;
create policy "invoice files add" on storage.objects
  for insert to authenticated with check (bucket_id = 'invoice-files' and (storage.foldername(name))[1] = auth.uid()::text and public.can_view('invoices'));
