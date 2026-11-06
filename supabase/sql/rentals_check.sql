-- Tik skaito: paskutiniai paėmimai (ar išsaugoti, kas ir kada keitė)
select id, left(replace(data->>'items', E'\n', ' / '), 50) as items, data->>'status' as status, data->>'pickupDate' as pickup,
       data->>'createdAt' as created, updated_at, updated_by, coalesce(data->>'deletedAt', '') as deleted
  from public.rentals order by updated_at desc nulls last limit 15;
select count(*) as rentals_total from public.rentals;
