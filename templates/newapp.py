import commands, paramiko
from _codecs import decode

from flask import Flask, render_template, request, url_for, redirect, abort
import time
import select
import paramiko
import sys

reload(sys)
sys.setdefaultencoding('utf8')

app = Flask(__name__)


def remote_command_executor(client, command):
    stdout_data = []
    stderr_data = []
    session = client.open_channel(kind='session')
    session.exec_command(command, )

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
        time.sleep(0.5)
        return stdout
    else:
        return "cannot perform the command, error: " + stderr

@app.route('/login.html')
@app.route('/')
def student():
    return render_template('login.html')


@app.route('/auth.html',methods = ['POST', 'GET'])
def result():
     if request.method == 'POST':

        address = request.form.get('address')
        user = request.form.get('username')
        password = request.form.get('pass')

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
        ostype = remote_command_executor(ssh, 'uname -o -s')
        osdes = remote_command_executor(ssh, 'lsb_release -d -s')
        kerver = remote_command_executor(ssh, 'uname -r')
        machinetype = remote_command_executor(ssh, 'uname -m')
        uptime = remote_command_executor(ssh, 'uptime -p')
        cpuname = remote_command_executor(ssh, '''lscpu | grep 'Model name' | cut -c 12-100''')
        selinux = remote_command_executor(ssh, '''sudo -S getsebool -a <<< %s''' %password)
        lshw = remote_command_executor(ssh, 'sudo -S whoami <<< %s' % password )
        return render_template('main_page.html', ostype=ostype, osdes=osdes, kerver=kerver, machinetype=machinetype, \
                               uptime=uptime[2:], cpuname=cpuname, selinux=selinux, lshw=lshw)


@app.route('/main_page.html')
def main_page():
    pass


if __name__ == '__main__':
    app.run(debug = True)

