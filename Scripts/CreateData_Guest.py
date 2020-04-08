import random

#sql = 'INSERT INTO `guest`.`sign_guest`(`id`, `realname`, `phone`, `email`, `sign`, `create_time`, `event_id`) ' \
#      'VALUES (1, '陈蒙1', '18514428812', 'chenmeng1@126.com', 0, '2020-04-08 15:57:34.000000', 8);'

sqlprefix = 'INSERT INTO `guest`.`sign_guest`(`id`, `realname`, `phone`, `email`, `sign`, `create_time`, `event_id`) ' \
      'VALUES ('
sqlpostfix = ');'
name = '陈蒙'
phone = 18114421812

for i in range(500):
    sql = sqlprefix + str(i+1) + ', '\
      + '\'' + name + str(i+1) + '\'' + ', '\
    + '\'' + str(phone+i+1) + '\'' + ', ' \
    + '\'' + 'chenmeng' + str(i+1) + '@126.com' + '\'' + ', ' \
    + '0' + ', ' \
    + '\'' + '2020-03-' + str(random.randrange(10, 30)) + ' ' + str(random.randrange(10,24)) + ':' + str(random.randrange(10,60)) \
    + ':' + str(random.randrange(10,60)) + '.' + '000000' + '\'' + ', ' \
    + str(random.randrange(1, 15)) \
      + sqlpostfix
    print(sql)