#############
###security auditing tool, with hardening suggestions###
##########



from flask import Flask, render_template, request, url_for, redirect, abort, jsonify
import time
import select
import paramiko
import sys
import os


nsec = 'NOT SECURE!'
sec = 'SECURE'
nd = 'NOT DETERMINED!'

address = ''
user = ''
password = ''


reload(sys)
sys.setdefaultencoding('utf8')

app = Flask(__name__)


def set_credentials(usr,passwd,add):
    global user
    global address
    global password

    user = usr
    address = add
    password = passwd


def get_credentials():
    return user,password,address


def remote_command_executor(client, command):
    stdout_data = []
    stderr_data = []
    session = client.open_channel(kind='session')
    session.exec_command(command)

    while True:
        if session.recv_ready():
            stdout_data.append(session.recv(4096))
        if session.recv_stderr_ready():
            stderr_data.append(session.recv_stderr(4096))
        if session.exit_status_ready():
            break

    exit_status = session.recv_exit_status()
    stdout = ''.join(stdout_data)
    stderr = ''.join(stderr_data)
    session.close()
    if exit_status == 0:
        return ['stdout',stdout]
    #     while stdout == '':
    #         remote_command_executor(client, command)
    #     return stdout
    else:
        return ['stderr', "ERROR WHILE CHECKING: " + stderr]


@app.route('/lshw.html')
def lshw():
    return render_template('lshw.html')


@app.route('/login.html')
@app.route('/')
def student():
    return render_template('login.html')


@app.route('/main.html', methods=['POST', 'GET'])
def result():

    if request.method == 'POST':

        which_btn = ''
        if "SELINUX" in request.form:
            which_btn = "SELINUX"

        elif "SSH root login permission" in request.form:
            which_btn = "SSH root login permission"

        elif "Shared Memory Security" in request.form:
            which_btn = "Shared Memory Security"

        elif "Preventing ip spoofing" in request.form:
            which_btn = "Preventing ip spoofing"

        elif "Minimum password policy" in request.form:
            which_btn = "Minimum password policy"

        elif "Different class password policy" in request.form:
            which_btn = "Different class password policy"

        elif "Prevent password brute-force" in request.form:
            which_btn = "Prevent password brute-force"

        if which_btn is '':
            address = request.form.get('address')
            user = request.form.get('username')
            password = request.form.get('pass')
            set_credentials(user,password,address)
        else:
            user, password, address = get_credentials()



        if not address:
            address = '127.0.0.1'
        if not user:
            user = 'root'

        i=1
        while True:
            try:
                ssh = paramiko.Transport((address, 22))
                # ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(username=user, password=password)
                break
            except paramiko.AuthenticationException:
                return render_template('failure.html', failure_cause="Authentication failed when connecting to %s" % address)
            except:
                i += 1
                time.sleep(2)

            # If we could not connect within time limit
            if i == 3:
                return render_template('failure.html', failure_cause="Could not connect to %s. request timeout..." % address)




        if which_btn is "SELINUX":
            s, ostype = remote_command_executor(ssh, 'uname -o -s')

        elif which_btn is "SSH root login permission":
            s, ostype = remote_command_executor(ssh, 'uname -o -s')

        elif which_btn is "Shared Memory Security":
            s, ostype = remote_command_executor(ssh, 'uname -o -s')

        elif which_btn is "Preventing ip spoofing":
            s, ostype = remote_command_executor(ssh, 'uname -o -s')

        elif which_btn is "Minimum password policy":
            s, ostype = remote_command_executor(ssh, 'uname -o -s')

        elif which_btn is "Different class password policy":
            s, ostype = remote_command_executor(ssh, 'uname -o -s')

        elif which_btn is "Prevent password brute-force":
            s, ostype = remote_command_executor(ssh, 'uname -o -s')





        s, ostype = remote_command_executor(ssh, 'uname -o -s')
        # print ostype
        s, osdes = remote_command_executor(ssh, 'lsb_release -d -s')
        # print(osdes)
        s, kerver = remote_command_executor(ssh, 'uname -r')
        # print(kerver)
        s, machinetype = remote_command_executor(ssh, 'uname -m')
        # print(machinetype)
        s, uptime = remote_command_executor(ssh, 'uptime -p')
        # print(uptime)
        s, cpuname = remote_command_executor(ssh, '''lscpu | grep 'Model name' | cut -c 12-100''')
        # print(cpuname)
        s, lshw = remote_command_executor(ssh, 'sudo -S lshw -html <<< %s' % password )


        try:
            os.remove('./templates/lshw.html')
        except:
            pass
        file=open("./templates/lshw.html","w")
        file.write(lshw)
        file.close()

        security_list = []
        s, selinux = remote_command_executor(ssh, '''sudo -S getsebool -a <<< %s''' %password)
        if s is 'stderr' and 'disable' in selinux:
            selinux_status = (nsec, 'enable SElinux using: getenforce on')
        elif s is 'stderr' and 'command not found' in selinux:
            selinux_status = (nsec, 'selinux is not installed! install it first.')
        elif s is 'stderr':
            selinux_status = (nd, 'we couldn\'t find needed information')
        else:
            selinux_status = (sec, 'It\'s ok, nothing to do')

        if selinux_status[0] is nd:
            security_list.append(("SELINUX", "We couldn't check!", selinux_status[0], selinux_status[1]))
        else:
            security_list.append(("SELINUX", "checking done!", selinux_status[0], selinux_status[1]))

        s, sshrootlogin = remote_command_executor(ssh, '''grep -i 'permitrootlogin' /etc/ssh/sshd_config | head -n1''')
        if 'yes' in sshrootlogin.lower() and sshrootlogin[:1] != '#':
            sshrootlogin_status = (nsec, 'in /etc/ssh/sshd_config, set \"permitrootlogin\" to \"no\" ')
        elif s is 'stderr':
            sshrootlogin_status = (nd, 'we couldn\'t find needed information')
        else:
            sshrootlogin_status = (sec, 'It\'s ok, nothing to do')

        if sshrootlogin_status[0] is nd:
            security_list.append(("SSH root login permission", "We couldn't check!", sshrootlogin_status[0], sshrootlogin_status[1]))
        else:
            security_list.append(("SSH root login permission",'checking done!', sshrootlogin_status[0], sshrootlogin_status[1]))

        s, sharedmemory = remote_command_executor(ssh, """grep -i 'none /run/shm tmpfs defaults,ro 0 0' /etc/fstab""")
        if s is 'stderr' and sharedmemory[22:] is '':
            sharedmemory_status = (nsec, 'run this command:\necho \'none /run/shm tmpfs defaults,ro 0 0\' >> /etc/fstab')
        elif 'none /run/shm tmpfs defaults,ro 0 0' in sharedmemory:
            sharedmemory_status = (sec, 'It\'s ok, nothing to do')
        else:
            sharedmemory_status = (nd, 'we couldn\'t find needed information')

        if sharedmemory_status[0] is nd:
            security_list.append(("Shared Memory Security", 'checking done!', sharedmemory_status[0], sharedmemory_status[1]))
        else:
            security_list.append(("Shared Memory Security", 'checking done!', sharedmemory_status[0], sharedmemory_status[1]))

        s, ipspoofing = remote_command_executor(ssh, """cat /etc/host.conf""")
        if "multi on" or "order hosts," in ipspoofing:
            ipspoofing_status = (nsec, 'in /etc/host.conf change:\n1:\'multi on\' to \'nospoof on\'\n2-change \'order hosts\' to \'hosts order\'')
        elif "nospoof on" and "hosts order" in ipspoofing:
            ipspoofing_status = (sec, 'It\'s ok, nothing to do')
        else:
            ipspoofing_status = (nd, 'we couldn\'t find needed information')

        if ipspoofing_status[0] is nd:
            security_list.append(("Preventing ip spoofing", "We couldn't check!", ipspoofing_status[0], ipspoofing_status[1]))
        else:
            security_list.append(("Preventing ip spoofing", "checking done!", ipspoofing_status[0], ipspoofing_status[1]))

        s, strong_password_len = remote_command_executor(ssh, """grep minlen /etc/security/pwquality.conf""")
        if s == 'stdout' and 'minlen' in strong_password_len and strong_password_len[:1] is not '#':
            len = 0
            for i in strong_password_len:
                if i.isdigit():
                    len = i
            if len >= 12:
                strong_password_len_status = (sec, 'It\'s ok, nothing to do')
        elif s == "stderr":
            strong_password_len_status = (nd, 'we couldn\'t find needed information')
        else:
            strong_password_len_status = (nsec, 'in /etc/security/pwquality.conf set the minlen to at least 12 and/or uncomment it!')

        if strong_password_len_status is nd:
            security_list.append(("Minimum password policy", "We couldn't check!", strong_password_len_status[0], strong_password_len_status[1]))
        else:
            security_list.append(("Minimum password policy", "checking done!", strong_password_len_status[0], strong_password_len_status[1]))

        s, strong_password_class = remote_command_executor(ssh, """grep minclass /etc/security/pwquality.conf""")
        if s == 'stdout' and 'minclass' in strong_password_class and strong_password_len[:1] is not '#':
            len = 0
            for i in strong_password_len:
                if i.isdigit():
                    len = i
            if len > 2:
                strong_password_class_status = (sec, 'It\'s ok, nothing to do')
        elif s == "stderr":
            strong_password_class_status = (nd, 'we couldn\'t find needed information')
        else:
            strong_password_class_status = (nsec, 'in /etc/pwquality.conf set the minclass to at least 3 and/or uncomment it!')

        if strong_password_class_status[0] is nd:
            security_list.append(("Different class password policy", "We couldn't check!", strong_password_class_status[0], strong_password_class_status[1]))
        else:
            security_list.append(("Different class password policy", "checking done!", strong_password_class_status[0], strong_password_class_status[1]))

        s, bf_prevent = remote_command_executor(ssh, "cat /etc/pam.d/login")
        if "auth required pam_tally2.so deny=4 even_deny_root" in bf_prevent:
            bf_prevent_status = (sec, 'It\'s ok, nothing to do')
        elif s == 'stderr':
            bf_prevent_status = (nd, 'we couldn\'t find needed information')
        else:
            bf_prevent_status = (nsec, 'add these lines to /etc/pam.d/login:\nauth required pam_tally2.so deny=4 even_deny_root\nunlock time=1200')

        if bf_prevent_status[0] is nd:
            security_list.append(("Prevent password brute-force", "We couldn't check!", bf_prevent_status[0], bf_prevent_status[1]))
        else:
            security_list.append(("Prevent password brute-force", "checking done!", bf_prevent_status[0], bf_prevent_status[1]))

        ssh.close()
        return render_template('main_page.html', ostype=ostype, osdes=osdes, kerver=kerver, machinetype=machinetype, \
                               uptime=uptime[2:], cpuname=cpuname, security_list=security_list)


# @app.route('/process', methods=['POST'])
# def process():
#     which_btn = ''
#
#     if "SELINUX" in request.form:
#         which_btn = "SELINUX"
#
#     elif "SSH root login permission" in request.form:
#         which_btn = "SSH root login permission"
#
#     elif "Shared Memory Security" in request.form:
#         which_btn = "Shared Memory Security"
#
#     elif "Preventing ip spoofing" in request.form:
#         which_btn = "Preventing ip spoofing"
#
#     elif "Minimum password policy" in request.form:
#         which_btn = "Minimum password policy"
#
#     elif "Different class password policy" in request.form:
#         which_btn = "Different class password policy"
#
#     elif "Prevent password brute-force" in request.form:
#         which_btn = "Prevent password brute-force"
#
#     return redirect('/main_page.html')


if __name__ == '__main__':
    app.run(debug = True)
