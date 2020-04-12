# 使用AES加密算法的接口文件

from django.http import JsonResponse
from sign.models import Event, Guest
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.db.utils import IntegrityError
import time, base64, json
from Crypto.Cipher import AES

# AES 加密算法
BS = 16
unpad = lambda s : s[0: - ord(s[-1])]


def decryptBase64(src):
    return base64.urlsafe_b64decode(src)


def decryptAES(src, key):
    src = decryptBase64(src)
    iv = b'1172311105789011'
    try:
        cryptor = AES.new(key, AES.MODE_CBC, iv)
        text = cryptor.decrypt(src).decode()
    # 如果加密字符串被篡改，则无法解密成功，抛出异常
    except ValueError:
        return '加密错误'

    return unpad(text)


def aes_encryption(request):
    app_key = 'W7v4D60fds2Cmk2U'
    if request.method == 'POST':
        data = request.POST.get('data', '')
    else:
        return '错误'

    # 解密
    decode = decryptAES(data, app_key)
    if decode == '加密错误':
        return '错误'
    else:
        # 转化为字典
        dict_data = json.loads(decode)
        return dict_data


def encryptBase64(src):
    return base64.urlsafe_b64encode(src)


def encryptAES(src, key):
    iv = b'1172311105789011'
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    BS = 16
    cryptor = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cryptor.encrypt(pad(src))
    return encryptBase64(ciphertext)

def get_AES_code(request):
    app_key = 'W7v4D60fds2Cmk2U'
    print(request)
    payload = {}
    for item in request.POST:
        print(item)
        print(request.POST.get(item))
        payload[item] = request.POST.get(item)
    print(payload)
    j = json.dumps(payload)
    print(j)
    encoded = encryptAES(j, app_key).decode()
    return JsonResponse({'data': encoded})


def add_event(request):
    dict_data = aes_encryption(request)
    if dict_data == '错误':
        return JsonResponse({'status': 10011, 'message': '请求错误'})

    eid = dict_data['eid']
    name = dict_data['name']
    limit = dict_data['limit']
    status = dict_data['status']
    address = dict_data['status']
    start_time = dict_data['start_time']

    if eid == '' or name == '' or limit == '' or address == '' or start_time == '':
        return JsonResponse({'status': 10021, 'message': '参数错误！'})

    result = Event.objects.filter(id=eid)
    print(result)
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


def add_guest(request):
    dict_data = aes_encryption(request)
    if dict_data == '错误':
        return JsonResponse({'status': 10011, 'message': '请求错误'})

    eid = dict_data['eid']
    realname = dict_data['realname']
    phone = dict_data['phone']
    email = dict_data['email']

    if eid == '' or realname == '' or phone == '':
        return JsonResponse({'status': 10021, 'message': '参数错误。'})

    result = Event.objects.filter(id=eid)
    if not result:
        return JsonResponse({'status': 10022, 'message': '发布会ID为空。'})

    result = Event.objects.get(id=eid).status
    if not result:
        return JsonResponse({'status': 10023, 'message': '发布会状态不可用。'})

    event_limit = Event.objects.get(id=eid).limit
    guest_limit = Guest.objects.filter(event_id=eid)

    if len(guest_limit) >= event_limit:
        return JsonResponse({'status': 10024, 'message': '参与人数已满。'})

    event_time = Event.objects.get(id=eid).start_time
    print(event_time)
    etime = str(event_time).split('+')[0]
    print(etime)
    timeArray = time.strptime(etime, "%Y-%m-%d %H:%M:%S")
    e_time = int(time.mktime(timeArray))

    now_time = str(time.time())
    ntime = now_time.split('.')[0]
    n_time = int(ntime)

    if n_time >= e_time:
        return JsonResponse({'status': 10025, 'message': '发布会已开始。'})

    try:
        Guest.objects.create(realname=realname, phone=int(phone), email=email, sign=0, event_id=int(eid))
    except IntegrityError:
        return JsonResponse({'status': 10026, 'message': '嘉宾手机号重复。'})
    return JsonResponse({'status': 200, 'message': '嘉宾添加成功。'})


def get_event_list(request):
    dict_data = aes_encryption(request)
    if dict_data == '错误':
        return JsonResponse({'status': 10011, 'message': '请求错误'})

    eid = dict_data['eid']
    name = dict_data['name']

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


def get_guest_list(request):
    dict_data = aes_encryption(request)
    if dict_data == '错误':
        return JsonResponse({'status': 10011, 'message': '请求错误'})
    if 'eid' in dict_data.keys():
        eid = dict_data['eid']
    else:
        eid = ''
    if 'phone' in dict_data.keys():
        phone = dict_data['phone']
    else:
        phone = ''

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


def user_sign(request):
    dict_data = aes_encryption(request)
    if dict_data == '错误':
        return JsonResponse({'status': 10011, 'message': '请求错误'})

    eid = dict_data['eid']
    phone = dict_data['phone']

    if eid == '' or phone == '':
        return JsonResponse({'status': 10021, 'message': '参数错误。'})

    result = Event.objects.filter(id=eid)
    if not result:
        return JsonResponse({'status': 10022, 'message': '发布会ID为空。'})

    result = Event.objects.get(id=eid).status
    if not result:
        return JsonResponse({'status': 10023, 'message': '发布会状态不可用。'})

    event_time = Event.objects.get(id=eid).start_time
    etime = str(event_time).split('+')[0]
    timeArray = time.strptime(etime, '%Y-%m-%d %H:%M:%S')
    e_time = int(time.mktime(timeArray))

    now_time = str(time.time())
    ntime = now_time.split('.')[0]
    n_time = int(ntime)

    if n_time >= e_time:
        return JsonResponse({'status': 10024, 'message': '发布会已开始。'})

    result = Guest.objects.filter(phone=phone)
    if not result:
        return JsonResponse({'status': 10025, 'message': '用户手机号不存在。'})

    result = Guest.objects.filter(event_id=eid, phone=phone)
    if not result:
        return JsonResponse({'status': 10026, 'message': '用户没有参与发布会。'})

    result = Guest.objects.filter(event_id=eid, phone=phone).sign
    if result:
        return JsonResponse({'status': 10027, 'message': '用户已签到。'})
    else:
        Guest.objects.filter(event_id=eid, phone=phone).update(sign='1')
        return JsonResponse({'status': 200, 'message': '用户签到成功。'})