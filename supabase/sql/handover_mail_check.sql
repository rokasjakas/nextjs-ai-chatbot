-- Tik skaito: ar numatomų išdavimų užduotys sukurtos, kam priskirtos, ar buvo pranešimai (diagnostika)
select t.id, left(t.title, 60) as title, t.created_at, t.due_at, t.remind,
       (select string_agg(coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email), ', ') from public.profiles p where p.id = t.created_by) as created_by,
       (select string_agg(coalesce(nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''), p.email) || case when p.id = t.created_by then ' (pats)' else '' end || ' <' || coalesce(p.email, '') || '>', ', ')
          from public.profiles p where p.id = any(t.assignees)) as assignees,
       (select count(*) from public.user_notifications n where n.tag = 'task-' || t.id) as notices
  from public.tasks t
 where t.title like 'Išdavimas:%'
 order by t.created_at desc
 limit 8;
select count(*) as planned_handovers from public.handovers where data->>'status' = 'numatyta';
