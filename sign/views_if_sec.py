from django.contrib import auth as django_auth
import base64
from django.http import JsonResponse
from sign.models import Event, Guest
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.db.utils import IntegrityError
import time, hashlib, json
from Crypto.Cipher import AES
import base64


# 用户认证
def user_auth(request):
    get_http_auth = request.META.get('HTTP_AUTHORIZATION', b'')
    auth = get_http_auth.split()
    try:
        auth_parts = base64.b64decode(auth[1]).decode('utf-8').partition(':')
    except IndexError:
        return '空'
    username, password = auth_parts[0], auth_parts[2]
    user = django_auth.authenticate(username=username, password=password)
    if user is not None:
        django_auth.login(request, user)
        return '成功'
    else:
        return '失败'


# 实现接口签名
def user_sign(request):
    if request.method == 'POST':
        client_time = request.POST.get('time', '')
        client_sign = request.POST.get('sign', '')
    else:
        return '错误'

    if client_time == '' or client_sign == '':
        return '签名为空'

    # 服务器时间
    now_time = time.time()
    server_time = str(now_time).split('.')[0]
    # 获取时间差
    time_diff = int(server_time) - int(client_time)
    if time_diff > 60:
        return '超时'

    # 签名检查
    md5 = hashlib.md5()
    sign_str = client_time + '&Guest-Bugmaster'
    sign_bytes_utf8 = sign_str.encode(encoding='utf-8')
    md5.update(sign_bytes_utf8)
    server_sign = md5.hexdigest()

    if server_sign != client_sign:
        return '签名失败'
    else:
        return '签名成功'

# AES 加密算法
BS = 16
unpad = lambda s : s[0: - ord(s[-1])]


def decryptBase64(src):
    return base64.urlsafe_b64decode(src)


def decryptAES(src, key):
    src = decryptBase64(src)
    iv = b'1172311105789011'
    cryptor = AES.new(key, AES.MODE_CBC, iv)
    text = cryptor.decrypt(src).decode()
    return unpad(text)

def aes_encryption(request):
    app_key = 'W7v4D60fds2Cmk2U'
    if request.method == 'POST':
        data = request.POST.get('data', '')
    else:
        return '错误'

    # 解密
    decode = decryptAES(data, app_key)
    # 转化为字典
    dict_data = json.loads(decode)
    return dict_data


# 带有用户认证的接口
def get_event_list(request):
    auth_result = user_auth(request)
    if auth_result == '空':
        return JsonResponse({'status': 10011, 'message': '用户认证为空。'})

    if auth_result == '失败':
        return JsonResponse({'status': 10012, 'message': '用户认证失败。'})

    eid = request.GET.get('eid', '')
    name = request.GET.get('name', '')

    if eid == '' and name == '':
        return JsonResponse({'status': 10021, 'message': '参数错误。'})

    if eid != '':
        event = {}
        try:
            result = Event.objects.get(id=eid)
        except ObjectDoesNotExist:
            return JsonResponse({'status': 10022, 'message': '查询结果为空'})
        else:
            event['name'] = result.name
            event['limit'] = result.limit
            event['status'] = result.status
            event['address'] = result.address
            event['start_time'] = result.start_time
            return JsonResponse({'status': 200, 'message': '成功'})

    if name != '':
        datas = []
        results = Event.objects.filter(name__contains=name)
        if results:
            for r in results:
                event = {}
                event['name'] = r.name
                event['limit'] = r.limit
                event['status'] = r.status
                event['address'] = r.address
                event['start_time'] = r.start_time
                datas.append(event)
            return JsonResponse({'status': 200, 'message': '成功'})
    else:
        return JsonResponse({'status': 10022, 'message': '查询结果为空'})


# 带有签名+时间戳的接口
def add_event(request):
    sign_result = user_sign(request)
    if sign_result == '错误':
        return JsonResponse({'status': 10011, 'message': '请求错误。'})
    elif sign_result == '签名为空':
        return JsonResponse({'status': 10012, 'message': '用户签名为空。'})
    elif sign_result == '超时':
        return JsonResponse({'status': 10013, 'message': '请求超时。'})
    elif sign_result == '签名失败':
        return JsonResponse({'status': 10014, 'message': '用户签名失败。'})

    eid = request.POST.get('eid', '')
    name = request.POST.get('name', '')
    limit = request.POST.get('limit', '')
    status = request.POST.get('status', '')
    address = request.POST.get('address', '')
    start_time = request.POST.get('start_time', '')

    if eid == '' or name == '' or limit == '' or address == '' or start_time == '':
        return JsonResponse({'status': 10021, 'message': '参数错误！'})

    result = Event.objects.filter(id=eid)
    if result:
        return JsonResponse({'status': 10022, 'message': '发布会ID已经存在。'})

    result = Event.objects.filter(name=name)
    if result:
        return JsonResponse({'status': 10023, 'message': '发布会名称已存在。'})

    if status == '':
        status = 1

    try:
        Event.objects.create(id=eid, name=name, limit=limit, address=address,
                             status=int(status), start_time=start_time)
    except ValidationError as e:
        error = 'start_time 格式不正确，格式应该为：YYYY-MM-DD HH:MM:SS。'
        return JsonResponse({'status': 10024, 'message': error})

    return JsonResponse({'status': 200, 'message': '添加发布会成功。'})

# 嘉宾查询接口-AES算法
def get_guest_list(request):
    dict_data = aes_encryption(request)
    if dict_data == '错误':
        return JsonResponse({'status': 10011, 'message': '请求错误'})

    eid = dict_data['eid']
    phone = dict_data['phone']

    if eid == '':
        return JsonResponse({'status': 10021, 'message': 'EID不可为空。'})

    if eid != '' and phone == '':
        datas = []
        results = Guest.objects.filter(event_id=eid)
        if results:
            for r in results:
                guest = {'realname': r.realname, 'phone': r.phone, 'email': r.email, 'sign': r.sign}
                datas.append(guest)
            return JsonResponse({'status': 200, 'message': '成功。', 'data': datas})
        else:
            return JsonResponse({'status': 200, 'message': '查询结果为空。'})

    if eid != '' and phone != '':
        guest = {}
        try:
            result = Guest.objects.get(phone=phone, event_id=eid)
        except ObjectDoesNotExist:
            return JsonResponse({'status': 200, 'message': '查询结果为空。'})
        else:
            guest['realname'] = result.realname
            guest['phone'] = result.phone
            guest['email'] = result.email
            guest['sign'] = result.sign
            return JsonResponse({'status': 200, 'message': '成功。', 'data': guest})