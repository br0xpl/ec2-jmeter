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

#logger
logger = logging.getLogger(__name__)

def runCommand(command, out=None, KeyboardInterruptCmd=None):
    logger.debug("Executing \"%s\"." % command)
    fh=None
    process=None
    if out:
        fh = logging.FileHandler(out, encoding='utf-8')
        fh.setFormatter(logging.Formatter("%(message)s"))
        fh.setLevel(logging.INFO)
        logger.addHandler(fh)
    
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    secondInt = False
    while process.poll() is None:
        try:
            o = process.stdout.readline().decode('utf-8').replace("\n","")
            while o:
                logger.info(o);
                o = process.stdout.readline().decode('utf-8').replace("\n","")
            o = process.stderr.readline().decode('utf-8').replace("\n","")
            while o:
                logger.warning(o);
                o = process.stderr.readline().decode('utf-8').replace("\n","")
        except KeyboardInterrupt as ex:
            if not secondInt:
                secondInt = True
                if KeyboardInterruptCmd:
                    runCommand(KeyboardInterruptCmd)
            else:
                if process:
                    process.terminate()
                logger.warning("Killed.")
                exit(1)
    if out:
        logger.removeHandler(fh)
        fh.close()

    
def start(testfile, instances, out, files=[]):
    state='extracting ip address'
    try:
        ip = instances[0].public_ip_address
        logger.info("Copying test file:")
        state='sending test files'
        runCommand("scp %s -o StrictHostKeyChecking=no %s ubuntu@%s:~/" % (ec2.config['ec2'].get('sshopt'),testfile,ip))

        logger.info("Running test:")
        state='running test'
        ips = ",".join([i.private_ip_address for i in instances])
        logger.debug("IPs: %s"%ips)
        runCommand("ssh %s -o StrictHostKeyChecking=no ubuntu@%s \"~/apache-jmeter-3.0/bin/jmeter -n -r -t %s -R%s %s\"" % (ec2.config['ec2'].get('sshopt',''), ip, testfile, ips, ec2.config['ec2'].get('jmeteropt','')), out, "ssh %s -o StrictHostKeyChecking=no ubuntu@%s \"~/apache-jmeter-3.0/bin/shutdown.sh;\"" % (ec2.config['ec2'].get('sshopt',''), ip) )

        for fn in files:
            logger.info("Copying back files (results):")
            state='retrieving results'
            runCommand("scp -r %s -o StrictHostKeyChecking=no ubuntu@%s:~/%s ./" % (ec2.config['ec2'].get('sshopt',''),ip,fn))
            runCommand("ssh %s -o StrictHostKeyChecking=no ubuntu@%s \"rm -rf %s\"" % (ec2.config['ec2'].get('sshopt',''),ip,fn))
        
    except subprocess.CalledProcessError as ex:
        logger.error("Error %s." % state)
        exit(1)

        

def startCmd(args):
    start(args.testfile, args.instances, args.out, args.files)

def propagate(files,instances):

    state='extracting ip address'
    try:
        for ip in [i.public_ip_address for i in instances]:
            for fn in files:
                logger.info("Copying %s to %s:"%(fn,ip))
                state='sending %s to %s'%(fn,ip)
                runCommand("scp -o StrictHostKeyChecking=no -r %s %s ubuntu@%s:~/" % (ec2.config['ec2'].get('sshopt',''),fn,ip))
    except subprocess.CalledProcessError as ex:
        logger.error("Error %s." % state)
        exit(1)


def propagateCmd(args):
    propagate(args.files,args.instances)
        
def print_usage(args):
    parser.print_usage(None)

        
if __name__ == '__main__':
    #set up logging
    logging.config.fileConfig('config',disable_existing_loggers=True)
    logger = logging.getLogger()
        
    parser = argparse.ArgumentParser()
    parser.set_defaults(func=print_usage)
    parser.add_argument('--ami', help='id of the AMI to use, default '+ec2.config['ec2'].get('ami'), default=ec2.config['ec2'].get('ami'), nargs='?')
    
    subparsers = parser.add_subparsers()
    parser_start = subparsers.add_parser('start')
    parser_start.add_argument('-o', '--out', help='jmeter output file')
    parser_start.add_argument('testfile', help='test file to run')
    parser_start.add_argument('files', metavar='file', help='file to copy back after tests (results)', nargs="*")
    parser_start.set_defaults(func=startCmd)
    
    parser_propagate = subparsers.add_parser('propagate')
    parser_propagate.add_argument('files', metavar='file', help='file to copy', nargs="+")
    parser_propagate.set_defaults(func=propagateCmd)
    
    args = parser.parse_args()
    args.instances = ec2.listInstances(ami=args.ami)
    if len(args.instances)==0:
        logger.error("No running instasnces! Consider running ec2.py add to create some instances.")
        exit(1)
    args.func(args)



