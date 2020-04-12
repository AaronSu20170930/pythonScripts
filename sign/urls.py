from django.urls import path
from sign import views_if, views_if_AES

'''没有安全机制的接口
path('add_event', views_if.add_event, name='add_event'),
path('add_guest', views_if.add_guest, name='add_guest'),
path('get_event_list/', views_if.get_event_list, name='get_event_list'),
path('get_guest_list/', views_if.get_guest_list, name='get_guest_list'),
path('user_sign', views_if.user_sign, name='user_sign')
'''

urlpatterns = [
    # AES加密接口
    path('add_event', views_if_AES.add_event, name='add_event'),
    path('add_guest', views_if_AES.add_guest, name='add_guest'),
    path('get_event_list', views_if_AES.get_event_list, name='get_event_list'),
    path('get_guest_list', views_if_AES.get_guest_list, name='get_guest_list'),
    path('user_sign', views_if_AES.user_sign, name='user_sign'),
    # 内部接口，用来获取AES加密编码，用于postman执行接口请求
    path('get_AES_code', views_if_AES.get_AES_code, name='get_AES_code')
]