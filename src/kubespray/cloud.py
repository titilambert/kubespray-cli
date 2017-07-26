#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This file is part of Kubespray.
#
#    Kubespray is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Foobar is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

"""
kubespray.cloud
~~~~~~~~~~~~

Run Instances on cloud providers and generate inventory
"""

import sys
import os
import re
import subprocess
import yaml
import json
import zipfile

import requests
from ati.terraform import tfstates, iter_states, iterresources


from kubespray.inventory import CfgInventory
from kubespray.common import get_logger, query_yes_no, run_command, which, id_generator, get_cluster_name
from ansible.utils.display import Display
display = Display()
playbook_exec = which('ansible-playbook')

try:
    import configparser
except ImportError:
    import ConfigParser as configparser


class Cloud(object):
    '''
    Run Instances on cloud providers and generates inventory
    '''
    def __init__(self, options, cloud):
        self.options = options
        self.cloud = cloud
        self.inventorycfg = options['inventory_path']
        self.playbook = os.path.join(options['kubespray_path'], 'local.yml')
        self.cparser = configparser.ConfigParser(allow_no_value=True)
        self.Cfg = CfgInventory(options, cloud)
        self.localcfg = os.path.join(
            options['kubespray_path'],
            'inventory/local.cfg'
        )
        self.instances = {'masters':
                          {'file': os.path.join(
                           options['kubespray_path'], 'masters_instances.json'),
                           'json': None
                           },
                          'nodes':
                          {'file': os.path.join(
                           options['kubespray_path'], 'nodes_instances.json'),
                           'json': None
                           },
                          'etcds':
                          {'file': os.path.join(
                           options['kubespray_path'], 'etcds_instances.json'),
                           'json': None
                           },
                          }
        self.logger = get_logger(
            options.get('logfile'),
            options.get('loglevel')
        )
        self.pbook_content = [{
            'gather_facts': False,
            'hosts': 'localhost',
            'become': False,
            'tasks': []
        }]
        self.logger.debug('''
             The following options were used to generate the inventory: %s
             ''' % self.options)

    def write_local_inventory(self):
        '''Generates inventory for local tasks'''
        self.cparser.add_section('local')
        self.cparser.set(
            'local',
            'localhost ansible_python_interpreter=python2 ansible_connection=local'
        )
        try:
            with open(self.localcfg, 'wb') as f:
                self.cparser.write(f)
        except IOError as e:
            display.error(
                'Cannot write inventory %s: %s'
                % (self.localcfg, e)
            )
            sys.exit(1)

    def write_playbook(self):
        '''Write the playbook for instances creation'''
        try:
            with open(self.playbook, "w") as pb:
                pb.write(yaml.dump(self.pbook_content, default_flow_style=True))
        except IOError as e:
            display.error(
                'Cant write the playbook %s: %s'
                % (self.playbook, e)
            )
            sys.exit(1)

    def write_inventory(self):
        '''Generate the inventory according the instances created'''
        for role in ['masters', 'nodes', 'etcds']:
            if '%s_count' % role in self.options.keys():
                with open(self.instances['%s' % role]['file']) as f:
                    self.instances['%s' % role]['json'] = json.load(f)
            else:
                self.instances['%s' % role]['json'] = []
        self.Cfg.write_inventory(self.instances['masters']['json'], self.instances['nodes']['json'], self.instances['etcds']['json'])

    def create_instances(self):
        '''Run ansible-playbook for instances creation'''
        cmd = [
            playbook_exec, '-i', self.localcfg, '-e',
            'ansible_connection=local', self.playbook
        ]
        if not self.options['assume_yes']:
            count = 0
            for role in ['masters', 'nodes', 'etcds']:
                if '%s_count' % role in self.options.keys():
                    count = count + self.options['%s_count' % role]
            if self.options['add_node']:
                display.warning(
                    '%s node(s) will be added to the current inventory %s' %
                    (count, self.inventorycfg)
                )
            if not query_yes_no('Create %s instances on %s ?' % (count, self.cloud)):
                display.display('Aborted', color='red')
                sys.exit(1)
        rcode, emsg = run_command('Create %s instances' % self.cloud, cmd)
        if rcode != 0:
            self.logger.critical('Cannot create instances: %s' % emsg)
            sys.exit(1)


class AWS(Cloud):

    def __init__(self, options):
        Cloud.__init__(self, options, "aws")
        self.options = options

    def gen_ec2_playbook(self):
        data = self.options
        data.pop('func')
        # Options list of ansible EC2 module
        self.options['image'] = self.options['ami']
        if 'security_group_id' in self.options.keys():
            self.options['group_id'] = self.options['security_group_id']
        if 'security_group_name' in self.options.keys():
            self.options['group'] = self.options['security_group_name']
        if 'tags' in self.options:
            self.options['instance_tags'] = {}
            for kv in self.options['tags']:
                k, v = kv.split("=")
                self.options['instance_tags'][k] = v
        ec2_options = [
            'aws_access_key', 'aws_secret_key', 'count', 'group_id',
            'group', 'instance_type', 'instance_profile_name', 'key_name', 'vpc_subnet_id',
            'image', 'instance_tags', 'assign_public_ip', 'region'
        ]
        # Define EC2 task
        for role in ['masters', 'nodes', 'etcds']:
            if '%s_count' % role in self.options.keys():
                ec2_task = {'ec2': {},
                            'name': 'Provision EC2 %s instances' % role,
                            'register': 'ec2_%s' % role}
                for opt in ec2_options:
                    if opt in self.options.keys():
                        d = {opt: self.options[opt]}
                        ec2_task['ec2'].update(d)
                ec2_task['ec2'].update({'count': self.options['%s_count' % role]})
                ec2_task['ec2'].update({'instance_type': self.options['%s_instance_type' % role]})
                ec2_task['ec2'].update({'instance_profile_name': self.options['%s_instance_profile_name' % role]})
                ec2_task['ec2'].update({'wait': True})
                self.pbook_content[0]['tasks'].append(ec2_task)
                # Write ec2 instances json
                self.pbook_content[0]['tasks'].append(
                    {'name': 'Generate a file with ec2 instances list',
                     'copy':
                         {'dest': '%s' % self.instances['%s' % role]['file'],
                          'content': '{{ec2_%s.instances}}' % role}}
                )
                # Wait for ssh task
                if self.options['use_private_ip']:
                    instance_ip = '{{ item.private_ip }}'
                else:
                    instance_ip = '{{ item.public_ip }}'
                self.pbook_content[0]['tasks'].append(
                    {'local_action': {'host': '%s' % instance_ip,
                                      'module': 'wait_for',
                                      'port': 22,
                                      'state': 'started',
                                      'timeout': 600},
                     'name': 'Wait until SSH is available',
                     'with_items': '{{ec2_%s.instances}}' % role}
                )
        self.write_local_inventory()
        self.write_playbook()


class GCE(Cloud):

    def __init__(self, options):
        Cloud.__init__(self, options, "gce")
        self.options = options

    def gen_gce_playbook(self):
        data = self.options
        data.pop('func')
        if 'tags' in self.options:
            self.options['tags'] = ','.join(self.options['tags'])
        # Options list of ansible GCE module
        gce_options = [
            'machine_type', 'image', 'zone', 'service_account_email',
            'pem_file', 'credentials_file', 'project_id', 'tags'
        ]
        # Define instance names
        cluster_name = 'k8s-' + get_cluster_name()
        for role in ['masters', 'nodes', 'etcds']:
            gce_instance_names = list()
            if '%s_count' % role in self.options.keys():
                for x in range(self.options['%s_count' % role]):
                    if self.options['add_node']:
                        current_inventory = self.Cfg.read_inventory()
                        cluster_name = '-'.join(
                            current_inventory['all']['hosts'][0]['hostname'].split('-')[:-2]
                        )
                        gce_instance_names.append(
                            cluster_name + '-%s' % id_generator()
                        )
                    elif 'cluster_name' in self.options.keys():
                        gce_instance_names.append(
                            self.options['cluster_name'] + '-%s' % id_generator()
                        )
                    else:
                        gce_instance_names.append(
                            cluster_name + '-%s' % id_generator()
                        )
                gce_instance_names = ','.join(gce_instance_names)
                # Define GCE task
                gce_task = {'gce': {},
                            'name': 'Provision GCE %s instances' % role,
                            'register': 'gce_%s' % role}
                for opt in gce_options:
                    if opt in self.options.keys():
                        d = {opt: self.options[opt]}
                        gce_task['gce'].update(d)
                gce_task['gce'].update({'machine_type': self.options['%s_machine_type' % role]})
                gce_task['gce'].update({'instance_names': '%s' % gce_instance_names})
                self.pbook_content[0]['tasks'].append(gce_task)
                # Write gce instances json
                self.pbook_content[0]['tasks'].append(
                    {'name': 'Generate a file with %s list' % role,
                     'copy':
                         {'dest': '%s' % self.instances['%s' % role]['file'],
                          'content': '{{gce_%s.instance_data}}' % role}}
                )
                # Wait for ssh task
                self.pbook_content[0]['tasks'].append(
                    {'local_action': {'host': '{{ item.public_ip }}',
                                      'module': 'wait_for',
                                      'port': 22,
                                      'state': 'started',
                                      'timeout': 600},
                     'name': 'Wait until SSH is available',
                     'with_items': '{{gce_%s.instance_data}}' % role}
                )
        self.write_local_inventory()
        self.write_playbook()


class OpenStack(Cloud):
    def __init__(self, options):
        Cloud.__init__(self, options, 'openstack')
        self.options = options

    def gen_openstack_playbook(self):
        data = self.options
        data.pop('func')

        openstack_credential_args = ('auth_url', 'username', 'password', 'project_name')
        openstack_auth = {}

        for cred_arg in openstack_credential_args:
            openstack_auth.update({cred_arg: self.options['os_%s' % cred_arg]})

        if self.options['floating_ip']:
            ip_type = 'public'
        else:
            ip_type = 'private'

        # Define instance names
        cluster_name = 'k8s-' + get_cluster_name()
        os_security_group_name = cluster_name + '-%s' % id_generator()

        self.pbook_content[0]['tasks'].append(
            {'name': 'Create security group',
               'os_security_group': {
                   'auth': openstack_auth,
                   'name': os_security_group_name,
                   'description': 'Contains security rules for the Kubernetes cluster',
                   'region_name': self.options['os_region_name'],
                   'state': 'present'}}
        )
        self.pbook_content[0]['tasks'].append(
            {'name': 'Add security rules',
               'os_security_group_rule': {
                   'auth': openstack_auth,
                   'security_group': os_security_group_name,
                   'protocol': '{{item}}',
                   'region_name': self.options['os_region_name'],
                   'state': 'present'},
               'with_items': ['tcp', 'udp', 'icmp']}
        )

        for role in ('masters', 'nodes', 'etcds'):
            os_instance_names = list()
            if '%s_count' % role in self.options.keys():
                for x in range(self.options['%s_count' % role]):
                    if self.options['add_node']:
                        current_inventory = self.Cfg.read_inventory()
                        cluster_name = '-'.join(
                            current_inventory['all']['hosts'][0]['hostname'].split('-')[:-1]
                        )
                        os_instance_names.append(
                            cluster_name + '-%s' % id_generator()
                        )
                    elif 'cluster_name' in self.options.keys():
                        os_instance_names.append(
                            self.options['cluster_name'] + '-%s' % id_generator()
                        )
                        os_security_group_name = self.options['cluster_name'] + '-%s' % id_generator()
                    else:
                        os_instance_names.append(
                            cluster_name + '-%s' % id_generator()
                        )
                self.pbook_content[0]['tasks'].append(
                    {'name': 'Create %s network ports' % role,
                       'os_port': {
                           'auth': openstack_auth,
                           'name': '{{item}}',
                           'region_name': self.options['os_region_name'],
                           'network': self.options['network'],
                           'allowed_address_pairs': [{'ip_address': self.options['kube_network']}],
                           'security_groups': (os_security_group_name,),
                           'state': 'present'},
                       'with_items': os_instance_names}
                )
                self.pbook_content[0]['tasks'].append(
                    {'name': 'Provision OS %s instances' % role,
                       'os_server': {
                           'auth': openstack_auth,
                           'name': '{{item}}',
                           'state': 'present',
                           'flavor': self.options['%s_flavor' % role],
                           'key_name': self.options['sshkey'],
                           'region_name': self.options['os_region_name'],
                           'auto_ip': self.options['floating_ip'],
                           'security_groups': (os_security_group_name,),
                           'nics': 'port-name={{ item }}',
                           'image': self.options['image']},
                       'register': 'os_%s' % role,
                       'with_items': os_instance_names}
                )
                # Write os instances json
                self.pbook_content[0]['tasks'].append(
                    {'name': 'Generate a file with OS %s instances list' % role,
                     'copy':
                         {'dest': '%s' % self.instances[role]['file'],
                          'content': '{{os_%s.results}}' % role}}
                )
                # Wait for ssh task
                self.pbook_content[0]['tasks'].append(
                    {'name': 'Wait until SSH is available',
                       'wait_for': {
                           'host': '{{item.openstack.%s_v4}}' % ip_type,
                           'port': 22,
                           'search_regex': 'SSH',
                           'state': 'started',
                           'delay': 10},
                       'with_items': '{{os_%s.results}}' % role}
                )
        self.write_local_inventory()
        self.write_playbook()


class Terraform(Cloud):
    TERRAFORM_DOWNLOAD_URL = "https://releases.hashicorp.com/terraform/{version}/terraform_{version}_linux_amd64.zip"
    TERRAFORM_VERSION_RE = re.compile(r"Terraform v(?P<version>\d\.\d\.\d)")

    def __init__(self, options):
        Cloud.__init__(self, options, "terraform")
        self.options = options
        self.path = options.get("tf_binary_folder")
        self.binary = "terraform"
        self.proxy = options.get("http_proxy", "")
        self.conf_path = options.get("tf_plan_folder")

    @property
    def version(self):
        terraform = os.path.join(self.path, self.binary)
        raw_version = subprocess.check_output([terraform, '--version'])
        m = re.match(self.TERRAFORM_VERSION_RE, raw_version)
        return m.group('version')

    @property
    def _config_env(self):
        """Return the subprocess env-compatible list from config_file"""
        config_env = {}
        for key, value in self.options.get('tf_vars', {}).iteritems():
            terra_key = 'TF_VAR_{}'.format(key)
            config_env[terra_key] = str(value)

        return config_env

    def _update(self, version):
        def _download(url):
            return requests.get(url, proxies=self.proxy).content

        filepath = os.path.join(self.path, self.binary)

        # Is there a need to update?
        if os.path.isfile(filepath):
            if self.version == version:
                self.logger.info('Terraform v{} up to date'.format(version))
                return None

        self.logger.info('Downloading terraform v{}...'.format(version))

        terraform_url = self.TERRAFORM_DOWNLOAD_URL.format(version=version)
        zippath = os.path.join(self.path, ''.join((self.binary, '.zip')))

        try:
            os.mkdir(self.path)
        except OSError:
            # Directory already exist.
            pass

        with open(zippath, 'w+') as file:
            file.write(_download(terraform_url))

        with zipfile.ZipFile(zippath, 'r') as zfile:
            zfile.extractall(os.path.join(self.path))

        os.chmod(os.path.join(self.path, self.binary), 0755)
        os.remove(zippath)


    def prepare(self):
        # TODO Get tf files
        self._update(self.options.get("tf_version"))

    def _get(self, conf_path):
        terraform = os.path.join(self.path, self.binary)
        subprocess.check_call([
            terraform,
            'get',
            conf_path
        ], cwd=self.path)

    def plan_instances(self):
        """The conf_path must include:

        ::

            ssh_keys/ansible.pub
            infra/*.tf

        :param conf_path: The path leading to ssh_keys/ and infra/
        :return:
        """
        terraform = os.path.join(self.path, self.binary)
        self._get(self.conf_path)

        subprocess.check_call([
            terraform,
            'plan',
            '-state={}'.format(os.path.join(self.options.get("tf_state_folder"), 'terraform.tfstate')),
            self.conf_path,
        ], env=self._config_env, cwd=self.path)

    def create_instances(self):
        '''Run ansible-playbook for instances creation'''
        self._update(self.options.get("tf_version"))
        # TODO
        # TERRAFORM
        terraform = os.path.join(self.path, self.binary)
        self._get(self.options.get('tf_plan_folder'))

        # Little protection against Microsoft errors.
        for _ in xrange(5):
            retval = subprocess.call([
                terraform,
                'apply',
                '-state={}'.format(os.path.join(self.options.get("tf_state_folder"), 'terraform.tfstate')),
                os.path.join(self.options.get('tf_plan_folder')),
            ], env=self._config_env, cwd=self.path)

            if retval == 0:
                break

        # Compatibility with other functions.
        if retval != 0:
            raise subprocess.CalledProcessError(retval, terraform)


    def plan_destroy_instances(self):
        terraform = os.path.join(self.path, self.binary)
        self._get(self.options.get('tf_plan_folder'))

        # Little protection against retryable errors.
        for _ in xrange(5):
            retval = subprocess.call([
                terraform,
                'plan',
                '-destroy',
                '-state={}'.format(os.path.join(self.options.get("tf_state_folder"), 'terraform.tfstate')),
                os.path.join(self.options.get('tf_plan_folder')),
            ],
                env=self._config_env,
                stderr=subprocess.STDOUT,
                cwd=self.path)

            if retval == 0:
                break

    def destroy_instances(self):
        terraform = os.path.join(self.path, self.binary)
        self._get(self.options.get('tf_plan_folder'))

        # Little protection against retryable errors.
        for _ in xrange(5):
            retval = subprocess.call([
                terraform,
                'destroy',
                '-state={}'.format(os.path.join(self.options.get("tf_state_folder"), 'terraform.tfstate')),
                '-force',
                os.path.join(self.options.get('tf_plan_folder')),
            ],
                env=self._config_env,
                stderr=subprocess.STDOUT,
                cwd=self.path)

            if retval == 0:
                break

        # Compatibility with other functions.
        if retval != 0:
            raise subprocess.CalledProcessError(retval, terraform)

    def write_inventory(self):
        '''Generate the inventory according the instances created'''
        from ati.terraform import tfstates, iter_states, iterresources, iterhosts
        hosts = iterhosts(iterresources(tfstates(self.options.get("tf_state_folder"))), None)


        self.instances['masters']['json'] = []
        self.instances['nodes']['json'] = []
        self.instances['etcds']['json'] = []
        for host in hosts:
            hostname = host[0]
            attrs = host[1]
            tags = host[2]
            for tag in tags:
                if tag == 'role=kube-master':
                    self.instances['masters']['json'].append(attrs)
                if tag == 'role=kube-node':
                    self.instances['nodes']['json'].append(attrs)
        # TODO handle add node
        self.options['add_node'] = None
        # TODO handle etcds == masters
        if self.instances['etcds']['json'] == []:
            self.instances['etcds']['json'] = self.instances['masters']['json']
        self.Cfg.write_inventory(self.instances['masters']['json'], self.instances['nodes']['json'], self.instances['etcds']['json'])

