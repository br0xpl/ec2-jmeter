#!/usr/bin/python
# -*- coding: utf-8 -*-

import boto3
import argparse
import subprocess
import ec2
import os
import configparser
import logging
import logging.config
import threading
import time

#logger
logger = logging.getLogger(__name__)

def reader(process, stream, f):
    while process.poll() is None:
        line = stream.readline().decode('UTF-8').replace("\n","")
        if line and line!="":
            f(line)

def runCommand(command, out=None, KeyboardInterruptCmd=None, stop=None, forceStop=None, loggerName='root'):
    logger = logging.getLogger(loggerName)
    logger.debug("Executing \"%s\"." % command)
    fh=None
    process=None
    if out:
        fh = logging.FileHandler(out, encoding='utf-8')
        fh.setFormatter(logging.Formatter("%(message)s"))
        fh.setLevel(logging.INFO)
        logger.addHandler(fh)
    
    process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    #flags = fcntl.fcntl(process.stdout, fcntl.F_GETFL) 
    #fcntl.fcntl(process.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    #flags = fcntl.fcntl(process.stderr, fcntl.F_GETFL) 
    #fcntl.fcntl(process.stderr, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    secondInt = False
    
    ol=''
    el=''

    threading.Thread(target=reader,args=(process, process.stdout, logger.info)).start()
    threading.Thread(target=reader,args=(process, process.stderr, logger.warning)).start()
    
    while process.poll() is None:
        try:
            if stop:
                if forceStop.is_set():
                    process.kill()
                    break
                if stop.is_set() and not secondInt:
                    secondInt = True
                    if KeyboardInterruptCmd:
                        runCommand(KeyboardInterruptCmd)

            time.sleep(1)
            # try:
            #     #logger.info(os.read(process.stdout.fileno(), 1024).decode('utf-8'))
            #     logger.info(process.stdout.readline())
            # except BlockingIOError as ex:
            #     pass
                
            # try:
            #     #logger.warning(os.read(process.stderr.fileno(), 1024).decode('utf-8'))
            #     logger.warning(process.stderr.readline())
            # except BlockingIOError as ex:
            #     pass

    
                
        except KeyboardInterrupt as ex:
            if not secondInt:
                secondInt = True
                if KeyboardInterruptCmd:
                    runCommand(KeyboardInterruptCmd)
            else:
                if process:
                    process.terminate()
                logger.warning("Killed.")
                break
    if out:
        logger.removeHandler(fh)
        fh.close()

    
def start(testfile, instances, out, files=[]):
    state='extracting ip address'
    try:
        if not 'jmeter' in ec2.config:
            ec2.config['jmeter'] = {}
        ip = instances[0].public_ip_address
        logger.info("Copying test file:")
        state='sending test files'
        runCommand("scp %s -o StrictHostKeyChecking=no %s %s@%s:~/" % (ec2.config['ec2'].get('sshopt'),testfile,ec2.config['ec2'].get('username','ubuntu'),ip))

        logger.info("Running test:")
        state='running test'
        ips = ",".join([i.private_ip_address for i in instances if i.public_ip_address!=ip])
        logger.debug("IPs: %s"%ips)
        runCommand("ssh %s -o StrictHostKeyChecking=no %s@%s \"%sjmeter -n -r -t %s -R%s %s\"" % (ec2.config['ec2'].get('sshopt',''),ec2.config['ec2'].get('username','ubuntu'), ip,ec2.config['jmeter'].get('binpath','~/apache-jmeter-3.0/bin/'), testfile, ips, ec2.config['ec2'].get('jmeteropt','')), out, "ssh %s -o StrictHostKeyChecking=no %s@%s \"%sshutdown.sh;\"" % (ec2.config['ec2'].get('sshopt',''),ec2.config['ec2'].get('username','ubuntu'), ip, ec2.config['jmeter'].get('binpath','~/apache-jmeter-3.0/bin/')) )

        logger.info("Copying back files (results):")
        state='retrieving results'
        runCommand("ssh %s -o StrictHostKeyChecking=no %s@%s \"tar czf results.tar.gz %s\"" % (ec2.config['ec2'].get('sshopt',''),ec2.config['ec2'].get('username','ubuntu'),ip,' '.join(files)))
        runCommand("scp -r %s -o StrictHostKeyChecking=no %s@%s:~/results.tar.gz ./" % (ec2.config['ec2'].get('sshopt',''),ec2.config['ec2'].get('username','ubuntu'),ip))
        runCommand("ssh %s -o StrictHostKeyChecking=no %s@%s \"rm -rf results.tar.gz %s\"" % (ec2.config['ec2'].get('sshopt',''),ec2.config['ec2'].get('username','ubuntu'),ip,' '.join(files)))
        
    except subprocess.CalledProcessError as ex:
        logger.error("Error %s." % state)
        exit(1)

        

def startCmd(args):
    start(args.testfile, args.instances, args.out, args.files)

def startSeparate(testfile, instances, out, files=[]):
    state='extracting ip address'
    secondInt = False
    try:
        if not 'jmeter' in ec2.config:
            ec2.config['jmeter'] = {}
        
        logger.info("Copying test file:")
        ec2.propagate([testfile], instances, False)
        
        logger.info("Running test!:")
        state='running test'
        stop = threading.Event()
        stop.clear()
        forceStop = threading.Event()
        forceStop.clear()
        no=1
        for i in instances:
            ip=i.public_ip_address
            if not os.path.exists(str(no)):
                os.makedirs(str(no))
            i.t = threading.Thread(target=runCommand, args=("ssh %s -o StrictHostKeyChecking=no %s@%s \"%sjmeter -n -t %s %s\"" % (ec2.config['ec2'].get('sshopt',''),ec2.config['ec2'].get('username','ubuntu'), ip,ec2.config['jmeter'].get('binpath','~/apache-jmeter-3.0/bin/'), testfile, ec2.config['ec2'].get('jmeteropt','')), str(no)+"/jmeter.log", "ssh %s -o StrictHostKeyChecking=no %s@%s \"%sshutdown.sh;\"" % (ec2.config['ec2'].get('sshopt',''),ec2.config['ec2'].get('username','ubuntu'), ip, ec2.config['jmeter'].get('binpath','~/apache-jmeter-3.0/bin/')) , stop, forceStop, "Host "+str(no)))
            #i.t = threading.Thread(target=runCommand, args=("ssh %s -o StrictHostKeyChecking=no %s@%s \"while true; do echo '%s'; sleep 1;done;\"" % (ec2.config['ec2'].get('sshopt',''),ec2.config['ec2'].get('username','ubuntu'), ip,str(no)), str(no)+"/jmeter.log", "ssh %s -o StrictHostKeyChecking=no %s@%s \"echo AAAA;\"" % (ec2.config['ec2'].get('sshopt',''),ec2.config['ec2'].get('username','ubuntu'), ip) , stop, forceStop, "Host "+str(no)))
            #i.t = threading.Thread(target=runCommand, args=("while true; do echo '%s'; sleep 1;done;" % str(no), str(no)+"/jmeter.log", "echo 'AAAA'" , stop, forceStop, "Host "+str(no)))
            i.t.start()
            l = logging.getLogger("Host "+str(no))
            l.propagate = False
            no=no+1

        chosen=0
        print("Choose buffer to show (or Ctrl+C to exit): ")
        while True:
            try:
                h = input()
                if h.isdigit():
                    if int(h)>0 and int(h)<=len(instances):
                        #subprocess.call("tail -f %s" % (h+"/jmeter.log"),shell=True)
                        o = logging.getLogger(chosen)
                        o.propagate = False
                        chosen = "Host "+h
                        l = logging.getLogger(chosen)
                        l.propagate = True
                        for line in [line.rstrip('\n') for line in open('%s/jmeter.log' % h)][-50:]:
                            logger.info(line)                        
                    else:
                        print("Out of range!")
                        
            except KeyboardInterrupt as ex:
                if not secondInt:
                    secondInt = True
                    stop.set()
                else:
                    forceStop.set()
                    logger.warning("Killed.")
                    break
        logger.info("Joining..")
        for i in instances:
            i.t.join()
                

        logger.info("Copying back files (results):")
        state='retrieving results'

        no=1
        for i in instances:
            runCommand("ssh %s -o StrictHostKeyChecking=no %s@%s \"tar czf results.tar.gz %s\"" % (ec2.config['ec2'].get('sshopt',''),ec2.config['ec2'].get('username','ubuntu'),i.public_ip_address,' '.join(files)))
            runCommand("scp -r %s -o StrictHostKeyChecking=no %s@%s:~/results.tar.gz ./%s/" % (ec2.config['ec2'].get('sshopt',''),ec2.config['ec2'].get('username','ubuntu'),i.public_ip_address,str(no)))
            runCommand("ssh %s -o StrictHostKeyChecking=no %s@%s \"rm -rf results.tar.gz %s\"" % (ec2.config['ec2'].get('sshopt',''),ec2.config['ec2'].get('username','ubuntu'),i.public_ip_address,' '.join(files)))
            no = no + 1
        
    except KeyboardInterrupt as ex:
        logger.error("Error %s." % state)
        exit(1)

        

def startSeparateCmd(args):
    startSeparate(args.testfile, args.instances, args.out, args.files)

    
        
def print_usage(args):
    parser.print_usage(None)

        
if __name__ == '__main__':
    #set up logging
    logging.config.fileConfig('config',disable_existing_loggers=True)
    logger = logging.getLogger()
        
    parser = argparse.ArgumentParser()
    #parser.set_defaults(func=print_usage)
    parser.add_argument('--ami', help='id of the AMI to use, default '+ec2.config['ec2'].get('ami'), default=ec2.config['ec2'].get('ami'), nargs='?')
    
    subparsers = parser.add_subparsers()
    parser_start = subparsers.add_parser('start')
    parser_start.add_argument('-o', '--out', help='jmeter output file')
    parser_start.add_argument('testfile', help='test file to run')
    parser_start.add_argument('files', metavar='file', help='file to copy back after tests (results)', nargs="*")
    parser_start.set_defaults(func=startCmd)

    parser_starts = subparsers.add_parser('startSeparate')
    parser_starts.add_argument('-o', '--out', help='jmeter output file')
    parser_starts.add_argument('testfile', help='test file to run')
    parser_starts.add_argument('files', metavar='file', help='file to copy back after tests (results)', nargs="*")
    parser_starts.set_defaults(func=startSeparateCmd)

    
    
    args = parser.parse_args()
    if args.func is None:
        print_usage(args)
    else:
        args.instances = ec2.listInstances(ami=args.ami)
        if len(args.instances)==0:
            logger.error("No running instasnces! Consider running ec2.py add to create some instances.")
            exit(1)
        args.func(args)



