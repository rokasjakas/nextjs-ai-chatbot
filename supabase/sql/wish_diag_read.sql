-- Linkėjimų patikra (tik skaitymas, tik kiekiai – be tekstų ir vardų)
select 'boards' as k, b.id, b.created_at, b.open, b.filter, b.swear, b.reactions, (select count(*) from public.wishes w where w.board_id = b.id) as total,
  (select count(*) from public.wishes w where w.board_id = b.id and w.status = 'new') as new_,
  (select count(*) from public.wishes w where w.board_id = b.id and w.status = 'approved') as approved,
  (select count(*) from public.wishes w where w.board_id = b.id and w.status = 'hidden') as hidden,
  (select max(created_at) from public.wishes w where w.board_id = b.id) as last_wish
from public.wish_boards b order by b.created_at;
select 'all' as k, count(*) from public.wishes;
select 'list_query' as k, b.id, jsonb_array_length(coalesce((select jsonb_agg((to_jsonb(w) - 'voter') || jsonb_build_object('counts', public.wish_rcounts(w.id)))
  from public.wishes w where w.board_id = b.id and w.status <> 'hidden'), '[]'::jsonb)) as n from public.wish_boards b;
select 'screen' as k, b.id, jsonb_array_length(public.wish_screen(b.screen_token)->'wishes') from public.wish_boards b;
