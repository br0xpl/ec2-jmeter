#!/usr/bin/python
# -*- coding: utf-8 -*-


import boto3
import botocore.config
import argparse
import configparser
import subprocess
import logging
import logging.config

#logger
logger = logging.getLogger(__name__)

#properties
config = configparser.ConfigParser()
config.read('config')

#ec2 config
if not 'ec2' in config:
    logger.error('No proper config file with ec2 section found!')
if 'pk' in config['ec2']:
    config['ec2']['sshopt']="%s -i %s"%(config['ec2'].get('sshopt',''),config['ec2'].get('pk'))    
if config['ec2'].get('aws_access_key_id'):
    session = boto3.Session(aws_access_key_id = config['ec2'].get('aws_access_key_id'), aws_secret_access_key = config['ec2'].get('aws_secret_access_key'), region_name=config['ec2'].get('region','eu-central-1'))
    ec2 = session.resource('ec2')
else:
    #try configs from ~/.aws/
    ec2=boto3.resource('ec2')


def create(count, instanceType):
    instances = list(ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']},{'Name': 'image-id', 'Values': [args.ami]}]))

    if (len(instances)>0):
        logger.error("There are some instances running: "+",".join([i.public_ip_address for i in instances]))
        logger.error("Leaving them running..")
        count -= len(instances)

    logger.info("Launching %d instance(s)." % count)
    if (count>0):
        ec2.create_instances(ImageId=args.ami, MinCount=count, MaxCount=count, KeyName=config['ec2'].get('keyName'),InstanceType=instanceType)



def createCmd(args):
    create(args.count, args.instanceType)

def terminate(ami,all=0):
    filter = [{'Name': 'instance-state-name', 'Values': ['running']}]
    if args.all==0:
        filter.append({'Name': 'image-id', 'Values': [args.ami]})
    instances = list(ec2.instances.filter(Filters=filter))
    if len(instances)==0:
        logger.info("There's nothing to terminate.")
    for i in instances:
        logger.info("Terminating %s.." % i.id)
        i.terminate()

def terminateCmd(args):
    terminate(args.ami, args.all)


def listInstances(ami=config['ec2'].get('ami'),all=0):
    filter = [{'Name': 'instance-state-name', 'Values': ['running']}]
    if all==0:
        filter.append({'Name': 'image-id', 'Values': [ami]})
    return list(ec2.instances.filter(Filters=filter))
    
def listInstancesCmd(args):
    instances = listInstances(args.ami,args.all)
    if len(instances)==0:
        logger.info("There are no instances running.")
    for i in instances:
        if args.ip=='none':
            logger.info("Machine %s, IP: %15s, private IP: %15s, image: %s." % (i.id, i.public_ip_address, i.private_ip_address, i.image.id))
        elif args.ip=='public':
            print("%s" % i.public_ip_address)
        else:
            print("%s" % i.private_ip_address)            

def sshCmd(args):
    instances = listInstances()
    selected = []
    if args.instance == 'all': 
        selected = instances
    elif not args.instance.isdigit():
        selected = [i for i in instances if i.id==args.instance]
    else:
        if int(args.instance)<=len(instances):
            selected.append(instances[int(args.instance)-1])
    if len(selected)==0:
        logger.error("No such instance found: %s." % args.instance)
        exit(1)
    for i in range(0, len(selected)):
        instance = selected[i]
        ip = instance.public_ip_address
        cmd = args.command.replace('%NODE%',str(i+1))
        if cmd!="":
            cmd = "'"+cmd+"'"
        subprocess.call("ssh %s -o StrictHostKeyChecking=no %s@%s %s"%(config['ec2'].get('sshopt',''),config['ec2'].get('username','ubuntu'),ip, cmd),shell=True)

def propagate(files,instances,back):

    state='extracting ip address'
    try:
        i=0
        for ip in [i.public_ip_address for i in instances]:
            i=i+1
            for fn in files:
                logger.info("Copying %s to %s:"%(fn,ip))
                state='sending %s to %s'%(fn,ip)
                if not back:
                    subprocess.call("scp -r %s -o StrictHostKeyChecking=no %s %s@%s:~/" % (config['ec2'].get('sshopt',''),fn,config['ec2'].get('username','ubuntu'),ip),shell=True)
                else:
                    subprocess.call("scp -r %s -o StrictHostKeyChecking=no %s@%s:~/%s ./%s/" % (config['ec2'].get('sshopt',''),config['ec2'].get('username','ubuntu'),ip,fn,str(i)),shell=True)
    except subprocess.CalledProcessError as ex:
        logger.error("Error %s." % state)
        exit(1)


def propagateCmd(args):
    propagate(args.files,listInstances(), args.back)

        
def print_usage(args):
    parser.print_usage(None)

if __name__ == '__main__':
    #set up logging
    logging.config.fileConfig('config',disable_existing_loggers=True)
    logger = logging.getLogger()
    
    parser = argparse.ArgumentParser()
    #parser.set_defaults(func=print_usage)
    parser.add_argument('--ami', help='id of the AMI to use, default '+config['ec2'].get('ami'), default=config['ec2'].get('ami'), nargs='?') 
    subparsers = parser.add_subparsers()
    parser_create = subparsers.add_parser('create')
    parser_create.add_argument('count', help='number of vms to create, default 1', type=int, default=1, nargs='?')
    parser_create.add_argument('-t', '--instanceType', help='type of instance, default=t2.medium', type=str, default='t2.medium', nargs='?')
    parser_create.set_defaults(func=createCmd)

    parser_list = subparsers.add_parser('list')
    parser_list.add_argument('-a','--all', help='show all vms running - even other AMIs', const=1, default=0, action='store_const')
    parser_list.add_argument('-i','--ip', help='list only IPs (public or private) one by one', default='none', const='public', nargs='?' )
    parser_list.set_defaults(func=listInstancesCmd)

    parser_ssh = subparsers.add_parser('ssh')
    parser_ssh.add_argument('-i','--instance', help='instance id or index (1 based integer) of the instance from the list, by default first; you can also use "all" to execute a command on all instances', type=str, default='1', nargs='?')
    parser_ssh.add_argument('command', help='Command to execute', type=str, default='', nargs='?')
    parser_ssh.set_defaults(func=sshCmd)
    

    parser_propagate = subparsers.add_parser('propagate')
    parser_propagate.add_argument('files', metavar='file', help='file to copy', nargs="+")
    parser_propagate.add_argument('-b', '--back', help='Copy from remote.', const=True, default=False, action='store_const')
    parser_propagate.set_defaults(func=propagateCmd)

    
    parser_terminate = subparsers.add_parser('terminate')
    parser_terminate.add_argument('-a','--all', help='terminate all vms running - even other AMIs', const=1, default=0, action='store_const')
    parser_terminate.set_defaults(func=terminateCmd)
    
    args = parser.parse_args()
    if args.func is None:
        print_usage(args)
    else:
        args.func(args)


