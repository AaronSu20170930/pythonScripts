
-- 统计已签到人数
select event_id as 发布会ID, Count(sign) as 签到人数 from sign_guest where sign=1 GROUP BY event_id;

-- 统计每个发布会有多少人报名
select event_id as 发布会ID, Count(*) as 报名人数 from sign_guest group by event_id;

-- 统计一共有多少人报名了发布会
select Count(*) as 总报名人数 from sign_guest;

