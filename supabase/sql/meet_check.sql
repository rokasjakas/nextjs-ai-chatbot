-- Tik skaito: ar Google Meet (skambučiai) prijungtas – kuri paskyra, kada (be rakto)
select 'meet' as k, coalesce((select email || ' · ' || connected_at::text from public.google_meet_auth where id = 1), 'NEPRIJUNGTA') as v;
