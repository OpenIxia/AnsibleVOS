

## Prerequisites

On the Vision NPB devices:
1. Keysight VOS version 5.2.0 or greater

On the Linux machine used to run Ansible playbooks:
1. Ansible 2.8.3 or greater installed
```
e.g. sudo pip3 install ansible
```
2. Python requests and requests-toolbelt packages installed
```
e.g. pip3 install requests requests-toolbelt
```

## Installing Keysight VOS modules

1. Get the VOS modules.
- download the archive from [ixiacom](https://support.ixiacom.com/support-overview/product-support/downloads-updates) website
<br>or
- using git clone 
```
git clone https://github.com/OpenIxia/AnsibleVOS.git
```
2. Find Ansible library location. 
<pre><code>ansible --version

    <em>ansible 2.8.3</em>
    <em>config file = /etc/ansible/ansible.cfg</em>
    <em>configured module search path = ['/home/testuser/.ansible/plugins/modules',' '/usr/share/ansible/plugins/modules']</em>
    <em>ansible python module location = <b>/usr/local/lib/python3.6/dist-packages/ansible</b></em>
    <em>executable location = /usr/local/bin/ansible</em>
    <em>python version = 3.6.8</em></pre></code>

3. Copy Keysight VOS modules, module_utils and plugins into Ansible library folder.
<pre><code>e.g. sudo cp -r modules module_utils plugins <b>/usr/local/lib/python3.6/dist-packages/ansible</b></pre></code>
4. Open a terminal where your playbooks are located and run your first test. 
```
ansible-playbook playbook_name.yml
```


## Keysight VOS Ansible modules notes

- For each Web API request that contains a password, a salt or a secret key, VOS Ansible modules will always return **changed**, even when you execute the same task twice. The reason for this behavior is the Web API does not return passwords in plain text and therefore the actual state cannot be fully compared with the desired stated described in the playbook.
- Several actions like **import**, **install_software**, **install_license** accept either a file that in this case will be used for all the equipments defined in hosts, or a directory and in this case the `vos_actions` module will search for files that contain in their name either the serial number or a particular sequence of characters specific to each target machine.
- Several actions like **export**, **save_logs** accept as path for the file to be downloaded either a file name, or a directory. If the path refers to a file, the serial number of each equipment would be appended to the provided path. If the path points to a directory, each file would be named following this convention: **NameOfTheAction_SerialNumber**.
- For the **install_software** action, you can either pass a single file that will be used for a set of equipments or you can pass a directory. In the later scenario, a regex function will try to find file names in that directory that match a predefined pattern, searching for proper installation files for each equipment. In case such files are not found, the execution will probably use a wrong file and a Web API error will be displayed.
- For some VOS actions the user need to increase the default **ansible_connect_timeout** and **ansible_command_timeout** values, as the restart process of some platforms requires more time. Our suggestion is: ansible_connect_timeout = 900, ansible_command_timeout = 600.
- For `vos_ports`, `vos_filters` and `vos_port_groups` synthetic selector keys have been added, besides **name**. The reason why a second key was needed is there are scenarios where the user wants to change the name of an object and Web API requires a way to identify that object. For `vos_filters` the selector is **filter**, for `vos_ports` is **port** and for `vos_port_groups` is **port_group**.
- In order to delete port groups or dynamic filters, consider in your playbook the keyword **delete**. For more context, please check the examples section of the 
_port_groups and nvos_filters .html documentation files.
- You are able to perform DELETE and PUT requests for multiple ports / port groups / dynamic filters at a time using special defined values for the corresponding selector. For more context, please check the examples section of the nvos_ports, nvos_port_groups and nvos_filters .html documentation files.
- You can run Ansible playbooks against a desired Keysight VOS version by adding in the inventory file the following pair **software_version: version_name**. If this argument is not present, Web API requests will consider the actual software version installed on the target equipment. Check the examples section of the modules for some context.
