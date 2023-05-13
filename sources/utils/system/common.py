
import os
import os.path
import socket

import settings
import managers

from utils.exception import VDOM_exception
# from utils.card import send_to_card_and_wait


direct = os.path.join(settings.TEMPORARY_LOCATION, "socket")
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
except:
    s = None


def console_debug(data):
    l = os.listdir(direct)
    for item in l:
        p = os.path.join(direct, item)
        err = False
        try:
            s.sendto(data, p)
        except:
            err = True
        if err:
            try:
                os.remove(p)
            except:
                pass
    try:
        sess = managers.request_manager.get_request().session()
        d = sess.value("debug_data")
        if d is None:
            d = []
        d.append(data)
        sess.value("debug_data", d)
    except:
        pass


def set_virtual_card(user, password, guid):
    print("SET VIRTUAL CARD")
    shost, sl, sp = ("partner.vdom-box-international.com", "card", "card")

    f = open('/etc/opt/virtcard', 'w')
    f.write("%s %s %s %s %s %s" % (shost, sl, sp, user, password, guid))
    f.close()

    # return send_to_card_and_wait("""virtualcard %s %s %s %s %s %s""" % (shost, sl, sp, user, password, guid), "carderror")


def login_virtual_card(user, password):
    if user == "1":
        return [("guid1", "name1"), ("guid2", "name2"), ("guid3", "name3")]
    else:
        raise VDOM_exception("Virtual card connection failed")
