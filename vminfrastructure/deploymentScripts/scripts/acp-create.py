#!/usr/bin/python
'''
Created on Nov 3, 2015

@author: wsmith
'''
from Tkinter import *
import ttk, boto3, time, thread, sys, os, datetime, string, re, socket
from boto3.session import Session
from subprocess import Popen, PIPE
import xml.etree.ElementTree as ET
from xml.dom import minidom

def main(argc, argv):
    acp = create_acp()
    acp.start()

class acp_params(object):
    def __init__(self):
        self.conf_file = os.path.join(os.getenv("HOME"), ".aws",
                            "acp_params.xml")
        self.tree = ET.ElementTree(file=self.conf_file)
        self.params = dict()

    def __mk_inst_conf__(self, inst_frame, conf):
        remote_access_frame = ttk.Frame(inst_frame, padding=(2,2,2,2))
        remote_access_frame.pack()
        Label(remote_access_frame, text='Instance Configuration',
              height=5, width=40, font=("Helvetica", 16)).pack()

        self.params['username'] = StringVar()
        self.params['username'].set(conf['username'])
        user_frame = ttk.Frame(remote_access_frame, padding=(2,2,2,2))
        user_label = Label(user_frame, text='Username', width=20)
        username = Entry(user_frame, textvariable=self.params['username'])
        user_label.pack(side=LEFT)
        username.pack()
        user_frame.pack()

        self.params['passwd'] = StringVar()
        self.params['passwd'].set(conf['password'])
        passwd_frame = ttk.Frame(remote_access_frame, padding=(2,2,2,2))
        passwd_label = Label(passwd_frame, text='Password', width=20)
        passwd = Entry(passwd_frame, textvariable=self.params['passwd'])
        passwd_label.pack(side=LEFT)
        passwd.pack()
        passwd_frame.pack()

        self.params['subnet'] = StringVar()
        self.params['subnet'].set(conf['subnet'])
        subnet_frame = ttk.Frame(remote_access_frame, padding=(2,2,2,2))
        subnet_label = Label(subnet_frame, text='Subnet', width=20)
        subnet = Entry(subnet_frame, textvariable=self.params['subnet'])
        subnet_label.pack(side=LEFT)
        subnet.pack()
        subnet_frame.pack()

        self.params['ntp'] = StringVar()
        self.params['ntp'].set(conf['ntp'])
        ntp_frame = ttk.Frame(remote_access_frame, padding=(2,2,2,2))
        ntp_label = Label(ntp_frame, text='NTP', width=20)
        ntp = Entry(ntp_frame, textvariable=self.params['ntp'])
        ntp_label.pack(side=LEFT)
        ntp.pack()
        ntp_frame.pack()

        security_frame = ttk.Frame(inst_frame, padding=(2,30,2,2))
        security_frame.pack()
        Label(security_frame, text='Firewall Options', font=("Helvetica", 12),
              height=5, width=40).pack()

        normal_frame = ttk.Frame(security_frame, padding=(2,2,2,2))
        normal_label = Label(normal_frame, text='Normal Firewall', width=20)

        idx, normal_sel, reduced_sel, options = 0, 0, 0, []
        for option in conf['security']['options']:
            if conf['security']['default_normal']['name']  == option['name']:
                normal_sel = idx
            if conf['security']['default_reduced']['name'] == option['name']:
                reduced_sel = idx
            idx += 1
            options.append(option['name'])

        self.params['firewall_name'] = StringVar()
        self.params['firewall_name'].set(options[normal_sel])

        w = apply(OptionMenu, (normal_frame,
                               self.params['firewall_name']) + tuple(options))
        normal_label.pack(side=LEFT)
        w.pack()
        normal_frame.pack(expand=1,fill=X)

        reduced_frame = ttk.Frame(security_frame, padding=(2,2,2,2))
        reduced_label = Label(reduced_frame, text='Open Firewall', width=20)
        self.params['reduced_firewall_name'] = StringVar()
        self.params['reduced_firewall_name'].set(options[reduced_sel])
        w = apply(OptionMenu, (reduced_frame,
                        self.params['reduced_firewall_name']) + tuple(options))
        reduced_label.pack(side=LEFT)
        w.pack()
        reduced_frame.pack(expand=1,fill=X)

        resources_frame = ttk.Frame(inst_frame, padding=(2,30,2,2))
        resources_frame.pack()
        Label(resources_frame, text='Instance Resources',
              font=("Helvetica", 12), height=5, width=40).pack()

        idx, laas_sel, dbaas_sel, srd_sel, acp_sel, options = 0, 0, 0, 0, 0, []
        for option in conf['resources']['options']:
            if conf['resources']['default']['laas'] == option:
                laas_sel = idx
            if conf['resources']['default']['dbaas'] == option:
                dbaas_sel = idx
            if conf['resources']['default']['srd'] == option:
                srd_sel = idx
            if conf['resources']['default']['single_acp'] == option:
                acp_sel = idx
            idx += 1
            options.append(option)

        self.params['laas_resource'] = StringVar()
        self.params['laas_resource'].set(options[laas_sel])
        self.params['dbaas_resource'] = StringVar()
        self.params['dbaas_resource'].set(options[dbaas_sel])
        self.params['srd_resource'] = StringVar()
        self.params['srd_resource'].set(options[srd_sel])
        self.params['single_acp_resource'] = StringVar()
        self.params['single_acp_resource'].set(options[acp_sel])

        laas_frame = ttk.Frame(resources_frame, padding=(2,2,2,2))
        laas_label = Label(laas_frame, text='Laas VM', width=20)
        w = apply(OptionMenu, (laas_frame,
                        self.params['laas_resource']) + tuple(options))
        laas_label.pack(side=LEFT)
        w.pack()
        laas_frame.pack(expand=1,fill=X)

        dbaas_frame = ttk.Frame(resources_frame, padding=(2,2,2,2))
        dbaas_label = Label(dbaas_frame, text='Dbaas VM', width=20)
        w = apply(OptionMenu, (dbaas_frame,
                        self.params['dbaas_resource']) + tuple(options))
        dbaas_label.pack(side=LEFT)
        w.pack()
        dbaas_frame.pack(expand=1,fill=X)

        srd_frame = ttk.Frame(resources_frame, padding=(2,2,2,2))
        srd_label = Label(srd_frame, text='Srd VM', width=20)
        w = apply(OptionMenu, (srd_frame,
                        self.params['srd_resource']) + tuple(options))
        srd_label.pack(side=LEFT)
        w.pack()
        srd_frame.pack(expand=1,fill=X)

        acp_frame = ttk.Frame(resources_frame, padding=(2,2,2,2))
        acp_label = Label(acp_frame, text='Single ACP VM', width=20)
        w = apply(OptionMenu, (acp_frame,
                        self.params['single_acp_resource']) + tuple(options))
        acp_label.pack(side=LEFT)
        w.pack()
        acp_frame.pack(expand=1,fill=X)

    def __mk_loadbal_conf__(self, loadbal_frame, conf):
        Label(loadbal_frame, text='Load Balancer Configuration',
              height=5, width=40, font=("Helvetica", 16)).pack()

        for bal_name, data in conf['loadbal'].iteritems():
            bal_frame = ttk.Frame(loadbal_frame,padding=(5,10,3,10))

            port_frame = ttk.Frame(bal_frame,padding=(3,3,3,3))
            Label(bal_frame, text=bal_name, font=("Helvetica", 12)).pack()
            Label(port_frame, text="Ports").pack(side=LEFT, padx=5)

            self.params[bal_name] = {'ports' : StringVar(),
                                       'health' : StringVar()}
            tmp = ""
            for n in conf['loadbal'][bal_name]['default_ports']:
                tmp += n + ', '
            self.params[bal_name]['ports'].set(tmp[:-2])
            port_entry = Entry(port_frame, width=50,
                textvariable=self.params[bal_name]['ports'])
            port_entry.pack()
            port_frame.pack()

            health_frame = ttk.Frame(bal_frame, padding=(3,3,3,3))
            Label(health_frame, text="Health Port").pack(side=LEFT, padx=5)
            self.params[bal_name]['health'].set(
                conf['loadbal'][bal_name]['default_health_port'])
            port_entry = Entry(health_frame, width=10,
                textvariable=self.params[bal_name]['health'])
            port_entry.pack()
            health_frame.pack(side=LEFT, anchor=W, expand=1)
            bal_frame.pack(anchor=W)

    def show_conf(self):
        conf = self.parse_conf()
        self.param_conf_top = Toplevel()
        self.param_conf_top.title("Configure ACP Params")

        param_frame = ttk.Frame(self.param_conf_top,
            padding=(12,3,12,6))
        inst_frame = ttk.Frame(param_frame,
                                    padding=(2,2,2,20),
                                    relief=GROOVE)
        self.__mk_inst_conf__(inst_frame, conf)
        loadbal_frame = ttk.Frame(param_frame,
                                    padding=(2,2,2,2),
                                    relief=GROOVE)
        self.__mk_loadbal_conf__(loadbal_frame, conf)
        inst_frame.pack(side=LEFT,fill='both')

        loadbal_frame.pack(fill='both')
        param_frame.pack()
        buttn_frame = ttk.Frame(self.param_conf_top, padding=(3,3,3,3))
        save_button = Button(buttn_frame, text ="Save",
                            command= lambda: self.__save_button__(conf))
        fac_def_button = Button(buttn_frame, text ="Set Factory Defaults",
                            command= lambda: self.__set_factory_def__(conf))
        cancel_button = Button(buttn_frame, text ="Cancel",
                            command= self.__cancel__button__)
        buttn_frame.pack()
        fac_def_button.pack(side=LEFT, padx=5)
        cancel_button.pack(side=LEFT, padx=5)
        save_button.pack(padx=5)

    def __save_button__(self, conf):
        conf['username'] = self.params['username'].get()
        conf['password'] = self.params['passwd'].get()
        conf['subnet'] = self.params['subnet'].get()
        conf['ntp'] = self.params['ntp'].get()

        conf['security']['default_normal']['name'] = \
                self.params['firewall_name'].get()
        conf['security']['default_reduced']['name'] = \
                self.params['reduced_firewall_name'].get()

        for option in conf['security']['options']:
            if conf['security']['default_normal']['name']  == option['name']:
                conf['security']['default_normal']['id'] = option['id']
            if conf['security']['default_reduced']['name'] == option['name']:
                conf['security']['default_reduced']['id'] = option['id']

        conf['resources']['default']['laas'] = \
                self.params['laas_resource'].get()

        conf['resources']['default']['dbaas'] = \
                self.params['dbaas_resource'].get()

        conf['resources']['default']['srd'] = \
                self.params['srd_resource'].get()

        conf['resources']['default']['single_acp'] = \
                self.params['single_acp_resource'].get()

        for bal_name, bal_info in conf['loadbal'].iteritems():
            tmp = self.params[bal_name]['ports'].get()
            tmp = tmp.replace(' ', '')
            conf['loadbal'][bal_name]['default_ports'] = \
                    tmp.split(',')
            conf['loadbal'][bal_name]['default_health_port'] = \
                self.params[bal_name]['health'].get()

        self.write_defaults(conf)


    def __set_factory_def__(self, conf):
        self.set_factory(conf)

        self.params['username'].set(conf['username'])
        self.params['passwd'].set(conf['password'])
        self.params['subnet'].set(conf['subnet'])
        self.params['ntp'].set(conf['ntp'])

        self.params['firewall_name'].set(
            conf['security']['default_normal']['name'])
        self.params['reduced_firewall_name'].set(
            conf['security']['default_reduced']['name'])

        self.params['laas_resource'].set(
                                    conf['resources']['default']['laas'])
        self.params['dbaas_resource'].set(
                                    conf['resources']['default']['dbaas'])
        self.params['srd_resource'].set(
                                    conf['resources']['default']['srd'])
        self.params['single_acp_resource'].set(
                                    conf['resources']['default']['single_acp'])

        for bal_name, bal_info in conf['loadbal'].iteritems():

            tmp = ""
            for n in conf['loadbal'][bal_name]['default_ports']:
                tmp += n + ', '
            self.params[bal_name]['ports'].set(tmp[:-2])

            self.params[bal_name]['health'].set(
                conf['loadbal'][bal_name]['default_health_port'])

    def __cancel__button__(self):
        self.param_conf_top.destroy()

    def parse_conf(self):
        conf = dict()
        conf['version'] = ""
        conf['username'] = ""
        conf['username_factory'] = ""
        conf['password'] =  ""
        conf['password_factory'] =  ""
        conf['subnet'] = ""
        conf['subnet_factory'] = ""
        conf['ntp'] = ""
        conf['ntp_factory'] = ""
        conf['security'] = {'options': [],
                            'factory_normal': {}, 'factory_reduced': {},
                            'default_normal': {}, 'default_reduced': {} }
        conf['resources'] = {'options': [], 'factory': {}, 'default': {}}
        conf['loadbal'] = {}

        root = self.tree.getroot()
        conf['version'] = root.find('version').text
        node = root.find('instance_conf')

        username = node.find('username')
        conf['username'] = username.find('default').text
        conf['username_factory'] = username.find('factory').text

        password = node.find('password')
        conf['password'] = password.find('default').text
        conf['password_factory'] = password.find('factory').text

        subnet = node.find('subnet')
        conf['subnet'] = subnet.find('default').text
        conf['subnet_factory'] = subnet.find('factory').text

        ntp = node.find('ntp')
        conf['ntp'] = ntp.find('default').text
        conf['ntp_factory'] = ntp.find('factory').text

        security = node.find('security')
        sel = security.find('selections')
        for option in sel.getiterator('option'):
            conf['security']['options'].append({
                    'name' : option.find('name').text,
                    'id' : option.find('id').text})

        factory = security.find('factory')
        normal = factory.find('normal')
        conf['security']['factory_normal'] = {
                'name' : normal.find('name').text,
                'id' : normal.find('id').text}

        reduced = factory.find('reduced')
        conf['security']['factory_reduced'] = {
                'name' : reduced.find('name').text,
                'id' : reduced.find('id').text}

        default = security.find('default')
        normal = default.find('normal')
        conf['security']['default_normal'] = {
                'name' : normal.find('name').text,
                'id' : normal.find('id').text}

        reduced = default.find('reduced')
        conf['security']['default_reduced'] = {
                'name' : reduced.find('name').text,
                'id' : reduced.find('id').text}

        resources = node.find('resources')
        selections = resources.find('selections')
        for option in selections.getiterator('option'):
            conf['resources']['options'].append(option.text)

        vm_types = resources.find('vm_types')
        for vm in vm_types:
            conf['resources']['factory'][vm.tag] = vm.find('factory').text
            conf['resources']['default'][vm.tag] = vm.find('default').text

        loadbalancers = root.find('load_balancers')
        for bal in loadbalancers:
            bal_name = bal.tag
            bal_dict = dict()
            default = bal.find('default')

            ports = default.find('ports').text
            bal_dict['default_ports'] = ports.split(',')
            bal_dict['default_health_port'] = default.find('health_port').text

            factory = bal.find('factory')
            ports = factory.find('ports').text
            bal_dict['factory_health_port'] = factory.find('health_port').text
            bal_dict['factory_ports'] = ports.split(',')

            conf['loadbal'][bal_name] = bal_dict

        return(conf)

    def write_defaults(self, conf):
        root = self.tree.getroot()
        node = root.find('instance_conf')

        #################################
        # defaults in instance security #
        #################################

        security = node.find('security')
        sel = security.find('selections')
        default = security.find('default')

        normal = default.find('normal')
        name = normal.find('name')
        id = normal.find('id')
        name.text = conf['security']['default_normal']['name']
        id.text = conf['security']['default_normal']['id']

        reduced = default.find('reduced')
        name = reduced.find('name')
        id = reduced.find('id')
        name.text = conf['security']['default_reduced']['name']
        id.text = conf['security']['default_reduced']['id']

        ##############################
        # defaults in inst resources #
        ##############################
        resources = node.find('resources')
        selections = resources.find('selections')

        vm_types = resources.find('vm_types')
        for vm, resource in  conf['resources']['default'].iteritems():
            for vm_type in vm_types:
                if vm == vm_type.tag:
                    inst_type = vm_type.find('default')
                    inst_type.text = resource

        #############################
        # defaults in load balancer #
        #############################
        balancers = root.find('load_balancers')
        for dict_bal_name, dict_bal_info in conf['loadbal'].iteritems():
            bal = balancers.find(dict_bal_name)
            bal_name = bal.tag
            if dict_bal_name == bal_name:
                default = bal.find('default')
                ports = default.find('ports')
                port_nums = ""
                for n in dict_bal_info['default_ports']:
                    port_nums += n + ','
                ports.text = port_nums[:-1]

                health = default.find('health_port')
                health.text = dict_bal_info['default_health_port']

        ##############################
        # defaults in user, password #
        ##############################

        username = node.find('username')
        username.find('default').text = conf['username']

        password = node.find('password')
        password.find('default').text = conf['password']

        subnet = node.find('subnet')
        subnet.find('default').text = conf['subnet']

        ntp = node.find('ntp')
        ntp.find('default').text = conf['ntp']

        try:
            self.tree.write(self.conf_file)
        except:
            raise Exception('Error writing: %s' % self.conf_file)

    def set_factory(self, conf):

        #################################
        # defaults in instance security #
        #################################

        conf['security']['default_normal'] = \
                conf['security']['factory_normal']

        conf['security']['default_reduced'] = \
                conf['security']['factory_reduced']

        ##################################
        # defaults in instance resources #
        ##################################

        for vm in conf['resources']['default']:
            conf['resources']['default'][vm] = \
                conf['resources']['factory'][vm]

        #############################
        # defaults in load balancer #
        #############################

        for bal_name in conf['loadbal']:
            bal_dict = conf['loadbal'][bal_name]
            bal_dict['default_ports'] = bal_dict['factory_ports']
            bal_dict['default_health_port'] = bal_dict['factory_health_port']


        ###########################################
        # defaults in user, password, subnet, ntp #
        ###########################################

        conf['username'] = conf['username_factory']
        conf['password'] = conf['password_factory']
        conf['subnet'] = conf['subnet_factory']
        conf['ntp'] = conf['ntp_factory']

        return(conf)

class create_acp(acp_params):
    def __init__(self):
        super(create_acp, self).__init__()
        self.version = '1.0.0'
        self.ec2 = boto3.resource('ec2')
        session = Session()
        self.resource = session.resource('ec2')
        self.bal_client = boto3.client('elb')
        self.amis = dict()
        self.dns_servers = []
        self.repo_servers = []
        self.acp_servers = []
        self.dns_name = ""
        self.repo_name = ""
        self.acp_name = ""

        self.__get_amis__()

        self.log = ""
        self.rt_win = Tk()
        self.__create_menu_bar__()

        self.prog = IntVar()

        self.dns_template_tk = StringVar()
        self.repo_template_tk = StringVar()
        self.acp_template_tk = StringVar()
        self.num_acp_tk = StringVar()
        self.cloud_name_tk = StringVar()

        # Use the variables below at start in order to avoid conflict if
        # user starts playing with buttons
        self.dns_template = ""     # self.dns_template_tk into here at start
        self.repo_template = ""    # self.repo_template_tk into here at start
        self.acp_template = ""     # self.acp_template_tk into here at start
        self.num_acp = ""          # self.num_acp_tk into here at start
        self.cloud_name = ""       # self.cloud_name_tk into here at start

        self.status = StringVar()
        self.status.set('')

        self.inst = dict() # use inst name as the key

        self.rt_win.title("Create Amazon ACP")
        self.mf = ttk.Frame(self.rt_win, padding=(30,3,12,12))
        self.left_frame = ttk.Frame(self.mf, padding=(3,3,12,12))
        self.right_frame = ttk.Frame(self.mf, padding=(3,3,12,12))

        self.__create_dns_frame__()
        self.__create_repo_frame__()
        self.__create_acp_frame__()
        self.__create_start_frame__()
        self.__create_status_frame__()
        self.__create_log_frame__()

        self.left_frame.pack(side=LEFT, expand=1)
        self.right_frame.pack(side=RIGHT)
        self.mf.pack(expand=1)
        self.backoffice_pem = os.path.join(os.getenv("HOME"), ".aws",
                                            "backoffice.pem")

    def start(self):
        self.rt_win.mainloop()

    def __show_about__(self):
        conf = self.parse_conf()
        about_toplevel = Toplevel()
        about_toplevel.title("About")
        about_label1 = Label(about_toplevel,
                             text='script version %s' % self.version,
                             height=2, width=40)
        about_label1.pack()
        about_label2 = Label(about_toplevel,
                             text='configuration file version %s' %
                                   conf['version'],
                             height=2, width=40)
        about_label2.pack()

    def __help_auth__(self):
         msg = """
         CREDENTIALS ARE CREATED AND DOWNLOADED FROM AMAZON'S WEBSITE

              https://console.aws.amazon.com/iam ->
              Identity and Access Management -> Users
              check box next to your name -> User Actions -> Manage Access Keys
              download your keys

         YOUR CREDENTIALS NEED TO BE SET IN THE FOLLOWING FILES:

             ~/.aws/credentials
                 [default]
                 aws_access_key_id=<YOUR ACCESS KEY ID>
                 aws_secret_access_key=<YOUR SECRET KEY>

              ~/.aws/config
                  [default]
                  region=us-west-2

         """
         msg = msg.replace('          ', '')
         help_toplevel = Toplevel()
         help_toplevel.title("Help Amazon Configuration")
         help_text = Text(help_toplevel, height=20, width=80)
         help_text.insert(INSERT, msg)
         help_text.pack()

    def __create_menu_bar__(self):
        self.menubar = Menu(self.rt_win)
        filemenu = Menu(self.menubar, tearoff=0)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.rt_win.quit)
        self.menubar.add_cascade(label="File", menu=filemenu)

        editmenu = Menu(self.menubar, tearoff=0)
        editmenu.add_command(label="Preferences",
                             command= self.show_conf)
        self.menubar.add_cascade(label="Edit", menu=editmenu)

        helpmenu = Menu(self.menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self.__show_about__)
        helpmenu.add_command(label="Authorization Configuration",
                             command=self.__help_auth__)
        self.menubar.add_cascade(label="Help", menu=helpmenu)
        self.rt_win.config(menu=self.menubar)

    def __create_dns_frame__(self):
        dns_frame = ttk.Frame(self.left_frame, padding=(20,20,3,3))
        Label(dns_frame, text="DNS Templates", fg='blue').pack()

        for dns in self.dns_servers:
            Radiobutton(dns_frame, text=dns,
                        variable = self.dns_template_tk,
                        value=dns).pack(anchor=W)
        dns_frame.pack(fill=X)

    def __create_repo_frame__(self):
        repo_frame = ttk.Frame(self.left_frame, padding=(20,20,3,3))
        Label(repo_frame, text="Repo Templates", fg='blue').pack()

        for repo in self.repo_servers:
            Radiobutton(repo_frame, text=repo,
                        variable = self.repo_template_tk,
                        value=repo).pack(anchor=W)
        repo_frame.pack(fill=X)

    def __create_acp_frame__(self):
        acp_frame = ttk.Frame(self.left_frame, padding=(20,20,3,3))
        Label(acp_frame, text="ACP Templates", fg='blue').pack()

        for acp in self.acp_servers:
            Radiobutton(acp_frame, text=acp,
                        variable = self.acp_template_tk,
                        value=acp).pack(anchor=W)
        acp_frame.pack(fill=X)

    def __start_button__(self):
        self.dns_template = self.dns_template_tk.get()
        self.repo_template = self.repo_template_tk.get()
        self.acp_template = self.acp_template_tk.get()
        self.num_acp = self.num_acp_tk.get()
        self.cloud_name = self.cloud_name_tk.get()

        self.log.delete('1.0', END)  # clear log window
        if self.dns_template == "":
            self.__log__( 'dns template required', red=True)
            return
        if self.repo_template == "":
            self.__log__( 'repo template required', red=True)
            return
        if self.acp_template == "":
            self.__log__( 'acp template required', red=True)
            return
        if self.num_acp == "":
            self.__log__( 'num acp required', red=True)
            return
        if self.cloud_name == "":
            self.__log__('cloud name required', red=True)
            return

        self.start_button.config(state=DISABLED)
        self.__log__( 'creating thread for deployment')
        thread.start_new_thread(self.__create_cloud__, ("Thread-1",))

    def __create_start_frame__(self):
        start_frame = ttk.Frame(self.right_frame, padding=(10,10,3,3))
        name_frame = ttk.Frame(start_frame, padding=(3,3,3,3))
        Label(name_frame, text="ACP Cloud Name", fg='blue').pack(side=LEFT)
        e = Entry(name_frame, textvariable=self.cloud_name_tk)
        e.pack()
        name_frame.pack()

        num_acp_frame = ttk.Frame(start_frame, padding=(3,3,3,3))
        Label(num_acp_frame, text="Num ACP Hosts", fg='blue').pack(side=LEFT)
        Radiobutton(num_acp_frame, text='1',
                        variable = self.num_acp_tk,
                        value='1').pack(side=LEFT)
        Radiobutton(num_acp_frame, text='8',
                        variable = self.num_acp_tk,
                        value='8').pack(side=LEFT)

        num_acp_frame.pack(fill=X)

        buttn_frame = ttk.Frame(start_frame, padding=(3,3,3,3))
        self.start_button = Button(buttn_frame, text ="Start",
                                command=self.__start_button__)
        self.start_button.pack(side=LEFT)
        buttn_frame.pack(side=LEFT)
        start_frame.pack()

    def __create_status_frame__(self):
        status_frame = ttk.Frame(self.right_frame, padding=(5,20,3,3))
        self.progressbar = ttk.Progressbar(status_frame, orient='horizontal',
                                length=300, mode='determinate',
                                variable=self.prog)
        self.progressbar.pack(padx=3, pady=10, anchor=W)
        name_frame = ttk.Frame(status_frame, padding=(3,3,3,3))
        name_frame.pack(side=LEFT)
        stat_label = Label(name_frame, text="Status: ").pack(side=LEFT)
        status = Label(name_frame,
                            textvariable = self.status,
                            fg='blue').pack(side=LEFT)
        status_frame.pack(expand=1, fill=X)

    def __create_log_frame__(self):
        log_frame = ttk.Frame(self.right_frame, padding=(5,10,3,3))
        name_frame = ttk.Frame(log_frame, padding=(3,3,3,3))
        Label(name_frame, text="LOG").pack()
        name_frame.pack()
        self.log = Text(log_frame, height=15, width=80, wrap=NONE)

        scry = Scrollbar(log_frame,orient=VERTICAL)
        scry.config(command=self.log.yview)
        self.log.config(yscrollcommand=scry.set)
        scry.pack(side=RIGHT, fill=Y)

        scrx = Scrollbar(log_frame, orient=HORIZONTAL)
        scrx.config(command=self.log.xview)
        self.log.config(xscrollcommand=scrx.set)
        scrx.pack(side=BOTTOM, fill=X)

        self.log.pack()
        log_frame.pack(fill=BOTH, expand=TRUE)

        self.log.tag_configure('blue', foreground='blue')
        self.log.tag_configure('red', foreground='red')

    def __status__(self, status):
        self.status.set(status)

    def __get_amis__(self):

        for ami in self.ec2.images.filter(Owners=['007113540878',
                                                  '007113540878']):
            if ami.tags == None:
                continue

            ami_type = None
            for tag in ami.tags:
                if 'type' in tag['Key'].lower():
                    ami_type = tag['Value'].lower()
                    break
                if 'sizedbaas' in tag['Key'].lower():
                    sizedbaas = int(tag['Value'])
                if 'sizelaas' in tag['Key'].lower():
                    sizelaas = int(tag['Value'])
                if 'sizesingleacp' in tag['Key'].lower():
                    sizesingleacp = int(tag['Value'])

            if ami_type == None:
                continue

            self.amis[ami.name] = {'id':ami.id, 'dbaas_size':sizedbaas,
                                    'laas_size':sizelaas,
                                    'single_acp_size':sizesingleacp}

            if 'dns' in ami_type.lower():
                self.dns_servers.append(ami.name)
            elif 'repo' in ami_type.lower():
                self.repo_servers.append(ami.name)
            elif 'acp' in ami_type.lower():
                self.acp_servers.append(ami.name)

    def __create_cloud__(self, thread_name):
        self.__log__('creating cloud: %s' % self.cloud_name)
        self.conf = self.parse_conf()
        self.prog.set(0)

        if self.num_acp == '1':
            max = 6
            self.progressbar.config(maximum=max)
            self.__create_single_acp_instances__()
            self.__configure_single_acp_hosts__()
            balancers = None
        else:
            max = 22
            self.progressbar.config(maximum=max)
            self.__create_mult_acp_instances__()
            balancers = self.__configure_mult_acp_hosts__()

        self.__disp_results__(balancers)

        self.start_button.config(state=NORMAL)
        self.menubar.entryconfigure(2, state=NORMAL)
        self.prog.set(max)
        self.__status__('%s cloud complete' % self.cloud_name)
        self.__log__('%s cloud complete' % self.cloud_name)

    def __max_fld__(self, fld, fld_size):
        if len(fld) > fld_size:
            return len(fld)
        else:
            return(fld_size)

    def __fld_lens__(self, data, fld_names):
        """
        Find the max length used for each field in all of the instances.
        Return them in a dictionary
        """
        fld_len = dict()
        for fname in fld_names:
            fld_len[fname] = 0

        for inst in data:
            for fld in fld_names:
                if fld in inst:
                    fld_len[fld] = self.__max_fld__(inst[fld], fld_len[fld])

        return(fld_len)

    def __disp_inst_hdr__(self, vm_data):
        hdr1_format = "| %s | %s | %s | %s |"
        hdr2_format = "|-%s-+-%s-+-%s-+-%s-|"
        self.__log__('Virtual Machines Created', blue=True)
        fld_names = ['name', 'id', 'public_ip', 'private_ip']
        fld_len = self.__fld_lens__(vm_data, fld_names)
        self.__log__(hdr1_format % ('Name'.center(fld_len['name']),
                             'ID'.center(fld_len['id']),
                             'Public IP'.center(fld_len['public_ip']),
                             'Private IP'.center(fld_len['private_ip'])))
        self.__log__(hdr2_format % ('-' * fld_len['name'],
                             '-' * fld_len['id'],
                             '-' * fld_len['public_ip'],
                             '-' * fld_len['private_ip']))
        fmt = "| %%-%ds | " % fld_len['name']
        fmt += "%%-%ds | "  % fld_len['id']
        fmt += "%%-%ds | "  % fld_len['public_ip']
        fmt += "%%-%ds | "  % fld_len['private_ip']

        return(fmt)

    def __disp_loadbal_hdr__(self, data):
        hdr1_format = "| %s | %s | %s |"
        hdr2_format = "|-%s-+-%s-+-%s-|"
        self.__log__('Load Balancers Created', blue=True)
        fld_names = ['name', 'dns', 'pub']
        fld_len = self.__fld_lens__(data, fld_names)
        self.__log__(hdr1_format % ('Name'.center(fld_len['name']),
                             'Public IP'.center(fld_len['pub']),
                             'DNS'.center(fld_len['dns'])))
        self.__log__(hdr2_format % ('-' * fld_len['name'],
                             '-' * fld_len['pub'],
                             '-' * fld_len['dns']))
        fmt = "| %%-%ds | " % fld_len['name']
        fmt += "%%-%ds | "  % fld_len['pub']
        fmt += "%%-%ds | "  % fld_len['dns']

        return(fmt)

    def __disp_results__(self, balancers):
        vm_data = []
        for name, inst in self.inst.iteritems():
            vm_data.append({'name':name, 'id':inst.instance_id,
                            'public_ip':inst.public_ip_address,
                            'private_ip':inst.private_ip_address})

        fmt = self.__disp_inst_hdr__(vm_data)
        for vm in vm_data:
            self.__log__(fmt %(vm['name'], vm['id'],
                               vm['public_ip'], vm['private_ip']))

        if balancers == None:
            return

        fmt = self.__disp_loadbal_hdr__(balancers)
        for bal in balancers:
            self.__log__(fmt % (bal['name'], bal['pub'], bal['dns']))

        self.__create_inventory__(vm_data)

    def __create_inventory__(self, vm_data):
        inventory_file = os.path.join(os.getenv("HOME"), "inventory")
        self.__log__('create inventory file', blue=True)
        try:
            fd = open(inventory_file, "w")
        except Exception as e:
                msg = "error creating inventory file: %s, %s %s" % \
                   (inventory_file, e, sys.exc_info()[2])
                self.__log__(msg, red=True)
                return

        for vm in vm_data:
            fd.write('[%s]\n' % vm['name'])
            fd.write('%s\n' % vm['private_ip'])
        fd.write('[ntp]\n')
        fd.write('%s\n' % self.conf['ntp'])
        fd.close()

        self.__log__('inventory file: %s' % inventory_file)

    def __configure_single_acp_hosts__(self):
        self.__conf_repo__()
        self.__conf_acp_host(self.inst[self.acp_name].public_ip_address,
                             self.acp_name)
        self.__conf_single_acp_dns__()

    def __mk_port_info__(self, ports):
        port_info = []
        for port in ports:
            port_info.append([int(port), 'tcp'])

        return port_info

    def __configure_mult_acp_hosts__(self):
        balancers = []
        self.__conf_repo__()

        for n in [1,2]:
            inst_name = self.cloud_name + '-dbaas' + '%d' % n
            self.__conf_acp_host(self.inst[inst_name].public_ip_address,
                                 inst_name)
        for n in [1,2,3]:
            inst_name = self.cloud_name + '-laas' + '%d' % n
            self.__conf_acp_host(self.inst[inst_name].public_ip_address,
                                 inst_name)

        for n in [1,2,3]:
            inst_name = self.cloud_name + '-srd' + '%d' % n
            self.__conf_acp_host(self.inst[inst_name].public_ip_address,
                                 inst_name)

        inst_names = []
        for n in [1,2,3]:
            inst_name = self.cloud_name + '-srd' + '%d' % n
            inst_names.append(inst_name)

        port_info = [[9100, 'tcp'], [22, 'tcp']]
        balancers.append(self.__mk_bal__('acpapi', inst_names,
                                         port_info, 4009))

        port_info = self.__mk_port_info__(
                        self.conf['loadbal']['etcdcluster']['default_ports'])
        balancers.append(self.__mk_bal__('etcdcluster', inst_names,
                                         port_info, 4002))

        port_info = self.__mk_port_info__(
                      self.conf['loadbal']['zookeepercluster']['default_ports'])
        balancers.append(self.__mk_bal__('zookeepercluster', inst_names,
                                         port_info, 4003))

        port_info = self.__mk_port_info__(
                        self.conf['loadbal']['swarmcluster']['default_ports'])
        balancers.append(self.__mk_bal__('swarmcluster', inst_names,
                                         port_info, 4004))

        port_info = self.__mk_port_info__(
                        self.conf['loadbal']['elk-ext']['default_ports'])
        balancers.append(self.__mk_bal__('elk-ext', inst_names,
                                         port_info, 4005))

        port_info = self.__mk_port_info__(
                        self.conf['loadbal']['maas']['default_ports'])
        balancers.append(self.__mk_bal__('maas', inst_names,
                                         port_info, 4006))

        for n in [1,2,3]:
            inst_name = self.cloud_name + '-laas' + '%d' % n
            inst_names.append(inst_name)
        port_info = [[9500, 'tcp'],[22, 'tcp']]
        balancers.append(self.__mk_bal__('lbaas-ext', inst_names,
                                         port_info, 4007))

        for n in [1,2]:
            inst_name = self.cloud_name + '-dbaas' + '%d' % n
            inst_names.append(inst_name)
        port_info = [[9999, 'tcp'], [8880, 'tcp'], [80, 'tcp'],
                     [49155, 'tcp'], [22, 'tcp']]
        balancers.append(self.__mk_bal__('dbaascluster', inst_names,
                                         port_info, 4008))

        self.prog.set(self.prog.get() + 1)
        self.__status__('Resolving IP addresses')
        self.__log__('Resolving IP addresses may take a few minutes',
                     blue=True)
        for bal in balancers:
            self.__log__('resolving IP addr for: %s, ' % bal['dns'])
            now = datetime.datetime.now()
            done = now + datetime.timedelta(0, 1200)
            while now < done:
                # wait until the DNS name resolves
                stat, results = self.__run_it__("ping -W3 -c2 %s" % bal['dns'])
                if stat == True:
                    break
                else:
                    time.sleep(15)
                    now = datetime.datetime.now()

            if now >= done:
                msg = 'failed to resolve DNS for load balancer: '
                msg += '%s   dns name: %s' % (bal['name'], bal['dns'])
                bal['pub'] = "error no ip"
                self.__log__(msg, red)
            else:
                bal['pub'] = socket.gethostbyname(bal['dns'])
                self.__log__('%s resolved to %s' % (bal['dns'], bal['pub']))

        self.prog.set(self.prog.get() + 1)
        self.__conf_mult_acp_dns__(balancers)
        return(balancers)

    def __conf_mult_acp_dns__(self, balancers):
        dns_pub = self.inst[self.dns_name].public_ip_address
        repo_priv = self.inst[self.repo_name].private_ip_address
        dns_file = '/var/named/internal.acp.arris.com.hosts'

        cmds = ["chattr -i /etc/resolv.conf",
                "chmod 666 /etc/resolv.conf",
                "sed '2,100d' -i /etc/resolv.conf",
                "echo search internal.acp.arris.com >> /etc/resolv.conf",
                "echo nameserver 127.0.0.1 >> /etc/resolv.conf",
                "chmod 644 /etc/resolv.conf",
                "chattr +i /etc/resolv.conf",
                "chmod 666 /etc/hosts",
                "echo 127.0.0.1 DNSServer >> /etc/hosts",
                "chmod 644 /etc/hosts",
                "sed '/management/s/0.0.0.0/%s/' -i %s" % (dns_pub,
                                                              dns_file),
                "sed '/dockerrepo/s/0.0.0.0/%s/' -i %s" % (repo_priv,
                                                              dns_file),
                "sed '/ntp/s/0.0.0.0/%s/' -i %s" % (self.conf['ntp'],
                                                    dns_file)]

        for bal in balancers:
            if 'dbaascluster' in bal['name']:
                cmds.append("sed '/^dbaascluster/s/0.0.0.0/%s/' -i %s" % \
                                (bal['pub'], dns_file))

            elif 'dockerrepo' in bal['name']:
                cmds.append("sed '/dockerrepo/s/0.0.0.0/%s/' -i %s" % \
                                (repo_priv,dns_file))

            elif 'elk-ext' in bal['name']:
                cmds.append("sed '/elk[^-]/s/0.0.0.0/%s/' -i %s" % \
                                (bal['pub'], dns_file))
                cmds.append("sed '/elk-ext/s/0.0.0.0/%s/' -i %s" % \
                                (bal['pub'], dns_file))

            elif 'etcdcluster' in bal['name']:
                cmds.append("sed '/etcdcluster/s/0.0.0.0/%s/' -i %s" % \
                                (bal['pub'], dns_file))

            elif 'lbaas-ext' in bal['name']:
                cmds.append("sed '/lbaas[^-]/s/0.0.0.0/%s/' -i %s" % \
                                (bal['pub'], dns_file))
                cmds.append("sed '/lbaas-client/s/0.0.0.0/%s/' -i %s" % \
                                (bal['pub'], dns_file))
                cmds.append("sed '/lbaas-ext/s/0.0.0.0/%s/' -i %s" % \
                                (bal['pub'], dns_file))

            elif 'maas' in bal['name']:
                cmds.append("sed '/maas/s/0.0.0.0/%s/' -i %s" % \
                                (bal['pub'], dns_file))

            elif 'zookeepercluster' in bal['name']:
                cmds.append("sed '/zookeepercluster/s/0.0.0.0/%s/' -i %s" % \
                                (bal['pub'], dns_file))

            elif 'swarmcluster' in bal['name']:
                cmds.append("sed '/swarmcluster/s/0.0.0.0/%s/' -i %s" % \
                                (bal['pub'], dns_file))
            else:
                self.__log__('err conf_mult_acp_dns, name: %s' % bal['name'],
                            red=True)

        cmds.append("sed '/advisorserver/s/0.0.0.0/%s/' -i %s" % \
                        (self.inst[self.cloud_name +'-laas3'].public_ip_address,
                        dns_file))
        cmds.append("service named restart")

        self.__status__('Configuring %s' % self.dns_name)
        self.__log__('configuring DNS at %s' % dns_pub, blue=True)
        self.__wait_for_ssh__(dns_pub, 120)

        for c in cmds:
            remote_cmd = "sudo %s" % c
            self.__log__(remote_cmd)
            stat, out = self.__exec_cmd__(dns_pub, remote_cmd)
            if stat == False:
                self.__log__("Error: %s" % out, red=True)

        self.__log__("DNS Configuration Complete")

    def __mk_bal__(self, bal_type, inst_names, port_info, health_port):
        bal = dict()
        Listeners = []
        Instances= []

        bal['name'] = self.cloud_name + '-' + bal_type
        bal['port_info'] = port_info
        bal['inst_names'] = inst_names

        tmp = "creating load balancer: %s   ports: " % bal['name']
        for port in port_info:
            tmp += "%d,%s, " % (port[0], port[1])
        tmp = tmp[:-2] + "   insts: "
        for n in inst_names:
            tmp += "%s, " % n
        self.__log__(tmp[:-2])

        for port in port_info:
            Listeners.append({'Protocol': port[1],
                              'LoadBalancerPort': port[0],
                              'InstanceProtocol': port[1],
                              'InstancePort': port[0],})

        try:
            res = self.bal_client.create_load_balancer(
                                    LoadBalancerName=bal['name'],
                                    Listeners=Listeners,
                                    Subnets=['subnet-55d4250c',],
                                    SecurityGroups=['sg-f4b85e90'])
        except Exception as e:
            msg = "Err creating balancer: %s %s" % (e, sys.exc_info()[2])
            self.__log__(msg, red=True)
            raise Exception(msg)

        bal['dns'] = res['DNSName']

        try:
            info = self.bal_client.configure_health_check(
                                        LoadBalancerName=bal['name'],
                                        HealthCheck={
                                            'Target': 'TCP:%d' % health_port,
                                            'Interval': 5,
                                            'Timeout': 2,
                                            'UnhealthyThreshold': 2,
                                            'HealthyThreshold': 2})
        except Exception as e:
            msg = "Make load bal(health check): %s %s" % (
                                                e, sys.exc_info()[2])
            self.__log__(msg, red=True)
            raise Exception(msg)

        try:
            info = self.bal_client.add_tags(
                                    LoadBalancerNames=[bal['name'],],
                                    Tags=[
                                          {
                                                'Key': 'CloudName',
                                                'Value': self.cloud_name
                                          },])
        except Exception as e:
            msg = "Make load bal(add tags): %s %s" % (
                                            e, sys.exc_info()[2])
            self.__log__(msg, red=True)
            raise Exception(msg)

        try:
            info = self.bal_client.enable_availability_zones_for_load_balancer(
                                    LoadBalancerName=bal['name'],
                                    AvailabilityZones=['us-west-2a',
                                                       'us-west-2b',
                                                       'us-west-2c'])
        except Exception as e:
            msg = "Make load bal(avail zones): %s %s" % (
                                            e, sys.exc_info()[2])
            self.__log__(msg, red=True)
            raise Exception(msg)

        for n in inst_names:
            Instances.append({'InstanceId' : self.inst[n].instance_id})

        try:
            self.bal_client.register_instances_with_load_balancer(
                                            LoadBalancerName=bal['name'],
                                            Instances=Instances)
        except Exception as e:
            msg = "Make load bal(reg instances): %s %s" % (
                                                e, sys.exc_info()[2])
            self.__log__(msg, red=True)
            raise Exception(msg)

        time.sleep(2)   # avoid amazon throttling errors
        return(bal)

    def __conf_repo__(self):
        repo_inst = self.inst[self.repo_name]
        repo_ip = repo_inst.public_ip_address
        dns_priv = self.inst[self.dns_name].private_ip_address
        cmds = ["chattr -i /etc/resolv.conf",
                "chmod 666 /etc/resolv.conf",
                "sed '2,100d' -i /etc/resolv.conf",
                "echo 'nameserver 8.8.8.8' >> /etc/resolv.conf",
                "yum -y install sshpass",
                "yum -y install ansible",
                "sed '2,100d' -i /etc/resolv.conf",
                "echo search internal.acp.arris.com >> /etc/resolv.conf",
                "echo nameserver %s >> /etc/resolv.conf" % dns_priv,
                "chmod 644 /etc/resolv.conf",
                "chattr +i /etc/resolv.conf"]

        self.__status__('Configuring %s' % self.repo_name)
        self.__log__('configuring repo at %s' % repo_ip, blue=True)
        self.__wait_for_ssh__(repo_ip, 120)

        self.__log__('set security temporarily to %s' %
                     self.conf['security']['default_reduced']['name'])
        repo_inst.modify_attribute(
                    Groups=[self.conf['security']['default_reduced']['id'],])

        for c in cmds:
            remote_cmd = "sudo %s" % c
            self.__log__(remote_cmd)
            stat, out = self.__exec_cmd__(repo_ip, remote_cmd)
            if stat == False:
                self.__log__("Error: %s" % out, red=True)

        self.__log__('set security back to %s' %
                     self.conf['security']['default_normal']['name'])
        repo_inst.modify_attribute(
                    Groups=[self.conf['security']['default_normal']['id'],])

        self.prog.set(self.prog.get() + 1)
        self.__log__("Repo Configuration Complete")

    def __conf_acp_host(self, acp_pub, acp_name):
        dns_priv = self.inst[self.dns_name].private_ip_address
        cmds = ["chattr -i /etc/resolv.conf",
                "chmod 666 /etc/resolv.conf",
                "sed '2,100d' -i /etc/resolv.conf",
                "echo search internal.acp.arris.com >> /etc/resolv.conf",
                "echo nameserver %s >> /etc/resolv.conf" % dns_priv,
                "chmod 644 /etc/resolv.conf",
                "chattr +i /etc/resolv.conf"]
        self.__status__('Configuring %s' % acp_name)
        self.__log__('configuring ACP(%s) at %s' % (acp_name, acp_pub),
                      blue=True)
        self.__wait_for_ssh__(acp_pub, 120)

        for c in cmds:
            remote_cmd = "sudo %s" % c
            self.__log__(remote_cmd)
            stat, out = self.__exec_cmd__(acp_pub, remote_cmd)
            if stat == False:
                self.__log__("Error: %s" % out, red=True)

        self.__set_hostname__(acp_pub, acp_name)

        self.prog.set(self.prog.get() + 1)
        self.__log__("%s Configuration Complete" % acp_name)

    def __conf_single_acp_dns__(self):
        dns_pub = self.inst[self.dns_name].public_ip_address
        acp_priv = self.inst[self.acp_name].private_ip_address
        acp_pub = self.inst[self.acp_name].public_ip_address
        repo_priv = self.inst[self.repo_name].private_ip_address
        dns_file = '/var/named/internal.acp.arris.com.hosts'
        cmds = ["chattr -i /etc/resolv.conf",
                "chmod 666 /etc/resolv.conf",
                "sed '2,100d' -i /etc/resolv.conf",
                "echo search internal.acp.arris.com >> /etc/resolv.conf",
                "echo nameserver 127.0.0.1 >> /etc/resolv.conf",
                "chmod 644 /etc/resolv.conf",
                "chattr +i /etc/resolv.conf",
                "chmod 666 /etc/hosts",
                "echo 127.0.0.1 DNSServer >> /etc/hosts",
                "chmod 644 /etc/hosts",
                "sed '/advisorserver/s/0.0.0.0/%s/' -i %s" % (acp_priv,
                                                              dns_file),
                "sed '/^dbaascluster/s/0.0.0.0/%s/' -i %s" % (acp_priv,
                                                              dns_file),
                "sed '/dockerrepo/s/0.0.0.0/%s/' -i %s" % (repo_priv,
                                                              dns_file),
                "sed '/elk[^-]/s/0.0.0.0/%s/' -i %s" % (acp_priv,
                                                              dns_file),
                "sed '/elk-ext/s/0.0.0.0/%s/' -i %s" % (acp_pub,
                                                              dns_file),
                "sed '/etcdcluster/s/0.0.0.0/%s/' -i %s" % (acp_priv,
                                                              dns_file),
                "sed '/lbaas[^-]/s/0.0.0.0/%s/' -i %s" % (acp_priv,
                                                              dns_file),
                "sed '/lbaas-client/s/0.0.0.0/%s/' -i %s" % (acp_priv,
                                                              dns_file),
                "sed '/lbaas-ext/s/0.0.0.0/%s/' -i %s" % (acp_pub,
                                                              dns_file),
                "sed '/maas/s/0.0.0.0/%s/' -i %s" % (acp_priv,
                                                              dns_file),
                "sed '/management/s/0.0.0.0/%s/' -i %s" % (acp_priv,
                                                              dns_file),
                "sed '/ntp/s/0.0.0.0/%s/' -i %s" % (self.conf['ntp'],
                                                    dns_file),
                "service named restart"]
        self.__status__('Configuring %s' % self.dns_name)
        self.__log__('configuring DNS at %s' % dns_pub, blue=True)
        self.__wait_for_ssh__(dns_pub, 120)

        for c in cmds:
            remote_cmd = "sudo %s" % c
            self.__log__(remote_cmd)
            stat, out = self.__exec_cmd__(dns_pub, remote_cmd)
            if stat == False:
                self.__log__("Error: %s" % out, red=True)

        self.prog.set(self.prog.get() + 1)
        self.__log__("DNS Configuration Complete")

    def __run_it__(self, cmd):
        p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        if p.returncode == 0:
            return(True, out)
        else:
            return(False, out+err)

    def __exec_cmd__(self, ip_addr, remote_cmd):
        """
        Execute command using ACP credentials first.  If they fail try
        again using Backoffice credentials.
        """
        ssh_opts = '-o StrictHostKeyChecking=no '
        ssh_opts += '-o UserKnownHostsFile=/dev/null'
        cmd_format = "sshpass -p%s ssh %s %s@%s '%s'"
        cmd = cmd_format % (self.conf['password'], ssh_opts,
                            self.conf['username'], ip_addr, remote_cmd)
        stat, results = self.__run_it__(cmd)
        if stat == True:
            return(True, results)

        prev_results = results
        ssh_opts += ' -o BatchMode=yes'
        cmd = "ssh %s -i %s %s@%s '%s'" % (ssh_opts, self.backoffice_pem,
                                          'centos', ip_addr, cmd)
        stat, results = self.__run_it__(cmd)
        if stat == True:
            return(True, results)
        else:
            return(False, prev_results+results)

    def __wait_for_ssh__(self, ip_addr, seconds):
        now = datetime.datetime.now()
        done = now + datetime.timedelta(0,seconds)
        while now < done:
            stat, out = self.__exec_cmd__(ip_addr, "ls")
            if stat == True:
                return(True)
            now = datetime.datetime.now()
            time.sleep(10)

        return(False)

    def __create_mult_acp_instances__(self):
        self.__create_dns__()
        self.__create_repo__()

        ami_id = self.amis[self.acp_template]['id']
        dbaas_vol_size = self.amis[self.acp_template]['dbaas_size']
        laas_vol_size = self.amis[self.acp_template]['laas_size']
        dbaas_resource = self.conf['resources']['default']['dbaas']
        laas_resource = self.conf['resources']['default']['laas']
        srd_resource = self.conf['resources']['default']['srd']

        for n in [1,2]:
            inst_name = self.cloud_name + '-dbaas' + '%d' % n
            self.__status__('creating '+ inst_name)
            self.__log__('creating %s' % inst_name, blue=True)
            self.__create_inst__(dbaas_resource, ami_id, inst_name,
                                 vol_size = dbaas_vol_size)

        for n in [1,2,3]:
            inst_name = self.cloud_name + '-laas' + '%d' % n
            self.__status__('creating '+ inst_name)
            self.__log__('creating %s' % inst_name, blue=True)
            self.__create_inst__(laas_resource, ami_id, inst_name,
                                 vol_size = laas_vol_size)

        for n in [1,2,3]:
            inst_name = self.cloud_name + '-srd' + '%d' % n
            self.__status__('creating '+ inst_name)
            self.__log__('creating %s' % inst_name, blue=True)
            self.__create_inst__(srd_resource, ami_id, inst_name)

    def __create_dns__(self):
        self.dns_name = self.cloud_name + '-dns'
        self.__status__('creating '+ self.dns_name)
        self.__log__('creating %s' % self.dns_name, blue=True)

        self.__create_inst__('t2.micro',
                            self.amis[self.dns_template]['id'],
                            self.dns_name)

    def __create_repo__(self):
        self.repo_name = self.cloud_name + '-repo'
        self.__status__('creating '+ self.repo_name)
        self.__log__('creating %s' % self.repo_name, blue=True)
        self.__create_inst__('t2.large',
                            self.amis[self.repo_template]['id'],
                            self.repo_name)

    def __create_single_acp_instances__(self):
        self.__create_dns__()
        self.__create_repo__()

        ami_id = self.amis[self.acp_template]['id']
        vol_size = self.amis[self.acp_template]['single_acp_size']
        acp_resource = self.conf['resources']['default']['single_acp']

        self.acp_name = self.cloud_name + '-acp'
        self.__status__('creating '+ self.acp_name)
        self.__log__('creating %s' % self.acp_name, blue=True)
        self.__create_inst__(acp_resource, ami_id, self.acp_name,
                             vol_size = vol_size)

        self.__status__('All Instances Created')
        self.__log__('All Instances Created')

    def __create_inst__(self, inst_type, ami_id, inst_name, vol_size=0):
        ebs = dict()
        dev_mappings = dict()
        ebs['DeleteOnTermination'] = True
        ebs['VolumeType'] = 'standard'
        if vol_size > 0:
            self.__log__('set vol size: %sGB' % vol_size)
            ebs['VolumeSize'] = vol_size
        dev_mappings['DeviceName'] = "/dev/sda1"
        dev_mappings['Ebs'] = ebs

        network = dict()
        network['SubnetId'] = self.conf['subnet']
        network['DeleteOnTermination'] = True
        network['AssociatePublicIpAddress'] = True
        network['DeviceIndex'] = 0

        try:
            insts = self.ec2.create_instances(ImageId=ami_id,
                                   MinCount=1, MaxCount=1,
                                   InstanceType=inst_type,
                                   BlockDeviceMappings=[dev_mappings],
                                   NetworkInterfaces=[network])
        except Exception as e:
            msg = "Err creating inst: %s %s" % (e, sys.exc_info()[2])
            self.__log__(msg, red=True)
            raise Exception(msg)

        self.__log__('%s created, waiting for running state' %
                         inst_name)
        inst = insts[0]
        id = inst.instance_id
        try:
            self.resource.Instance(id=id).wait_until_running()
        except Exception as e:
            self.__log__('instance does not exist yet', red=True)
            time.sleep(1)
            self.__log__('try again')
            try :
                self.__log__('%s created, waiting for running state' %
                         inst_name)
                self.resource.Instance(id=id).wait_until_running()
            except Exception as e:
                msg = "failed waiting: %s %s" % (e, sys.exc_info()[2])
                self.__log__(log, red=True)
                raise Exception(msg)

        self.__log__('%s is running' % inst_name)
        self.__log__('%s setting inst-name and security groups' %
                        inst_name)
        tags = [{'Key': 'Name', 'Value': inst_name },
                {'Key': 'CloudName', 'Value': self.cloud_name}]
        tag = inst.create_tags(Resources=[id,], Tags=tags)

        self.__log__('set security to %s' %
                     self.conf['security']['default_normal']['name'])
        inst.modify_attribute(Groups=
                            [self.conf['security']['default_normal']['id'],])

        self.__log__('%s -> pub ip: %s   priv ip: %s' %
                        (inst_name, inst.public_ip_address,
                         inst.private_ip_address))
        self.inst[inst_name] = inst
        self.__log__('%s instance creation complete' % inst_name)

        self.prog.set(self.prog.get() + 1)

    def __set_hostname__(self, ip_addr, host_name):
        stat, rel = self.__get_centos_rel__(ip_addr)
        if stat == False:
            self.__log__("Unable to set hostname for: %s, %s" % (
                                            host_name, ip_addr), red=True)
            return
        self.__log__('Configure hostname for centos release: %s' % rel)

        if rel.startswith('6'):
            cmds = ["chmod 666 /etc/sysconfig/network",
                    "sed '/HOSTNAME/d' -i /etc/sysconfig/network",
                    "echo HOSTNAME=%s >> /etc/sysconfig/network" % host_name,
                    "chmod 644 /etc/sysconfig/network",
                    "hostname %s" % host_name,
                    "chmod 666 /etc/hosts",
                    "echo 127.0.0.1  %s >> /etc/hosts" % host_name,
                    "chmod 644 /etc/hosts"]
        else:
            cmds = ['hostnamectl set-hostname %s' % host_name,
                    'systemctl restart systemd-hostnamed']

        for c in cmds:
            remote_cmd = "sudo %s" % c
            self.__log__(remote_cmd)
            stat, out = self.__exec_cmd__(ip_addr, remote_cmd)
            if stat == False:
                self.__log__("Error: %s" % out, red=True)

    def __get_centos_rel__(self, ip_addr):
        remote_cmd = 'cat /etc/centos-release'
        self.__log__(remote_cmd)
        stat, out = self.__exec_cmd__(ip_addr, remote_cmd)
        if stat == False:
            self.__log__("Error: %s" % out, red=True)
            return(False, "")
        else:
            rel = re.sub(r'.*release ([0-9][^ ]*).*', r'\1', out,
                        flags=re.DOTALL)
            return(True, rel)

    def __log__(self, msg, blue=FALSE, red=False):
        if red == True:
            self.log.insert(END, msg + '\n', ('red'))
        elif blue == True:
            self.log.insert(END, msg + '\n', ('blue'))
        else:
            self.log.insert(END, msg + '\n')
        self.log.see(END)

if __name__ == '__main__': main(len(sys.argv), sys.argv)
