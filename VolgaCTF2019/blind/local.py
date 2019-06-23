#!/usr/bin/env python
from __future__ import print_function
import os
import sys
import shlex
import subprocess
#from private_key import d
#n = 30864197530864197530864197530864197530864197530864199402469135802469135802469135802469135802469135802469163647
n = 22678885995497859237359837409834658408010390603936675736906855360800963199438301063705092375804444129441479327781570397188117238152040732414190434618440730435564133857204879042192155745904265933737075192414720502471456820073834429901830596917771255092067979581702360147524982558130023326060635370345862693395971869907940712129405277579994126963033117569220694056962409098580444767623301289484274757401588341649346335157605898367428193861286290895380925167854010745241200707970331694303405414452197886125252783330442313175217854953051589125237129765483421120589637801644296802772127692576775865505959688257172232082269
e = 65537
#d = 8790623786732854892825596397624412333660544594825993649985334832062634677951216700320260141429862350868813073
d = 1568285263768501732818328320511629642875064318126264773176402162063414029019552015208378147415135584397039600737080993027702630930696379133941301092371841712833615433127126841619464574827015780577329215130743142304356963372974314300549251037297089095888613813025849461961689136723457981196984901634305044882572884429636926589307978155389584182278408495724608043621991280167408620534651830073093136272231629494826910936016933211209155663316948185922751060616648342097882005697026783567976368285160591751813938075036356113489495762878707450272084659301801564293123458920666027344212043777409046272492671188377827505457

"""
    Utils
"""


def run_cmd(cmd):
    try:
        args = shlex.split(cmd)
        return subprocess.check_output(args)
    except Exception as ex:
        return str(ex)


"""
    Signature
"""

class RSA:
    def __init__(self, e, d, n):
        self.e = e
        self.d = d
        self.n = n

    def sign(self, message):
        message = message.encode('hex')
        #print("In sign message: message = " + str(message))
        message = int(message, 16)
        #print("In sign message: message = " + str(message))
        return pow(message, self.d, self.n)

    def verify(self, message, signature):
        message = int(message.encode('hex'), 16)
        verify = pow(signature, self.e, self.n)
        return message == verify


"""
	Keys
"""

#n = 26507591511689883990023896389022361811173033984051016489514421457013639621509962613332324662222154683066173937658495362448733162728817642341239457485221865493926211958117034923747221236176204216845182311004742474549095130306550623190917480615151093941494688906907516349433681015204941620716162038586590895058816430264415335805881575305773073358135217732591500750773744464142282514963376379623449776844046465746330691788777566563856886778143019387464133144867446731438967247646981498812182658347753229511846953659235528803754112114516623201792727787856347729085966824435377279429992530935232902223909659507613583396967
#e = 65537


"""
    Communication utils
"""

def read_message():
    return sys.stdin.readline()


def send_message(message):
    sys.stdout.write('{0}\r\n'.format(message))
    sys.stdout.flush()


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


"""
    Main
"""

def check_cmd_signatures(signature):
    cmd1 = 'exit'
    cmd2 = 'leave'
    assert (signature.verify(cmd1, signature.sign(cmd1)))
    assert (signature.verify(cmd2, signature.sign(cmd2)))


class SignatureException(Exception):
    pass


if __name__ == '__main__':
    signature = RSA(e, d, n)
    check_cmd_signatures(signature)
    try:
        while True:
            send_message('Enter your command:')
            message = read_message().strip()
            (sgn, cmd_exp) = message.split(' ', 1)
            eprint('Accepting command {0}'.format(cmd_exp))
            eprint('Accepting command signature: {0}'.format(sgn))

            cmd_l = shlex.split(cmd_exp)
            cmd = cmd_l[0]
            if cmd == 'ls' or cmd == 'dir':
                ret_str = run_cmd(cmd_exp)
                send_message(ret_str)

            elif cmd == 'cd':
                try:
                    sgn = int(sgn)
                    if not signature.verify(cmd_exp, sgn):
                        raise SignatureException('Signature verification check failed')
                    os.chdir(cmd_l[1])
                    send_message('')
                except Exception as ex:
                    send_message(str(ex))

            elif cmd == 'cat':
                try:
                    sgn = int(sgn)
                    if not signature.verify(cmd_exp, sgn):
                        raise SignatureException('Signature verification check failed')
                    if len(cmd_l) == 1:
                        raise Exception('Nothing to cat')
                    ret_str = run_cmd(cmd_exp)
                    send_message(ret_str)
                except Exception as ex:
                    send_message(str(ex))

            elif cmd == 'sign':
                try:
                    send_message('Enter your command to sign:')
                    message = read_message().strip()
                    #print("In reading sign command: message = " + str(message))
                    message = message.decode('base64')
                    #print("In reading sign command: message length = " + str(len(message)))
                    #print("In reading sign command: message = " + str(message))
                    #eprint("In sign: message = " + message)
                    cmd_l = shlex.split(message)
                    sign_cmd = cmd_l[0]
                    #print("sign_cmd = " + str(sign_cmd))
                    #print(str(len(sign_cmd)))
                    if sign_cmd not in ['cat', 'cd']:
                        sgn = signature.sign(sign_cmd)
                        send_message(str(sgn))
                    else:
                        send_message('Invalid command')
                except Exception as ex:
                    send_message(str(ex))

            elif cmd == 'exit' or cmd == 'leave':
                sgn = int(sgn)
                if not signature.verify(cmd_exp, sgn):
                    raise SignatureException('Signature verification check failed')
                break

            else:
                send_message('Unknown command {0}'.format(cmd))
                break

    except SignatureException as ex:
        send_message(str(ex))
        eprint(str(ex))

    except Exception as ex:
        send_message('Something must have gone very, very wrong...')
        eprint(str(ex))

    finally:
        pass