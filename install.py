#!/bin/sh
''''which python3  >/dev/null 2>&1 && exec python3  "$0" "$@" # '''
''''which python  >/dev/null 2>&1 && exec python  "$0" "$@" # '''
''''which python2 >/dev/null 2>&1 && exec python2 "$0" "$@" # '''

import sys
import os
from shutil import copy2, copyfile
import time
import argparse
import textwrap
import xml.etree.ElementTree as ET
from glob import glob

# Backward compatibility for python2
try:
    input = raw_input
except NameError:
    pass

SCRIPT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
DEBUG = False

class CommentedTreeBuilder(ET.TreeBuilder):
    def comment(self, data):
        self.start(ET.Comment, {})
        self.data(data)
        self.end(ET.Comment)


def find_in_repo_etc(pattern):
    """
    returns a list of files starting from the etc of the package directory
    that match the specified file pattern
    """
    return list(glob(os.path.join(SCRIPT_DIRECTORY, 'etc', pattern)))

def get_files_to_install():
    return find_in_repo_etc('duo-filter-*.jar')

def remove_existing_duo_installation(jira_lib_path):
    file_list = glob(os.path.join(jira_lib_path, 'duo-*.jar')) + glob(os.path.join(jira_lib_path, 'DuoWeb-*.jar'))
    for matching_files in file_list:
        debug("removing {filename}".format(filename=matching_files))
        os.remove(matching_files)

def get_xml_path(root_install_dir, xml_name, is_jira=False):
    dir_str = 'confluence'
    if is_jira:
        dir_str = 'atlassian-jira'
    return os.path.join(root_install_dir, dir_str, 'WEB-INF', xml_name)

def fail(msg):
    print(msg)
    sys.exit(1)

def succeed(msg):
    print(msg)
    sys.exit(0)

def info(msg):
    print(msg)

def warn(msg):
    print(msg)

def debug(msg):
    global DEBUG
    if DEBUG:
        print(msg)

def valid_paths(paths):
    return all([os.path.exists(path) for path in paths])

def get_security_xml_location(root, web_xml_tag, filter_name_param):
    count = 0
    for child in root:
        count += 1
        filter_name = child.findtext(filter_name_param)
        if child is not None and child.tag == web_xml_tag and filter_name == "security":
            return count

def update_xml_websdk_2(duo_param_xml, new_client_id, new_secret, new_host, new_rediruri, new_failmode):
    if "ikey" in duo_param_xml:
        duo_param_xml["ikey"][0].text = "client.Id"
        duo_param_xml["ikey"][1].text = new_client_id
    if "skey" in duo_param_xml:
        duo_param_xml["skey"][0].text = "client.Secret"
        duo_param_xml["skey"][1].text = new_secret
    if "filter" in duo_param_xml:
        redirect_uri_xml_str = redirect_uri_str_xml.format(redirect_url=new_rediruri)
        redirect_uri_xml = ET.fromstring(redirect_uri_xml_str)
        duo_param_xml["filter"].append(redirect_uri_xml)
    update_xml_parameters(duo_param_xml, new_host, new_failmode)

def update_xml_websdk_4(duo_param_xml, new_client_id, new_secret, new_host, new_rediruri, new_failmode):
    if "client.Id" in duo_param_xml:
        duo_param_xml["client.Id"].text = new_client_id
    if "client.Secret" in duo_param_xml:
        duo_param_xml["client.Secret"].text = new_secret
    if "redirecturi" in duo_param_xml:
        duo_param_xml["redirecturi"].text = new_rediruri
    update_xml_parameters(duo_param_xml, new_host, new_failmode)

def update_xml_parameters(duo_param_xml, new_host, new_failmode):
    if "host" in duo_param_xml:
        duo_param_xml["host"].text = new_host
    if "fail.Open" in duo_param_xml:
        duo_param_xml["fail.Open"].text = str(new_failmode)
    # "fail.Open" is not a required parameter so it might not exist in the web.xml
    elif "filter" in duo_param_xml:
        fail_mode_xml_str = fail_mode_str_xml.format(fail_mode=new_failmode)
        fail_mode_xml = ET.fromstring(fail_mode_xml_str)
        duo_param_xml["filter"].append(fail_mode_xml)
        duo_param_xml["fail.Open"] = True

def need_update_xml_param(duo_param_xml, new_client_id, new_secret, new_host, new_rediruri, new_failmode):
    if ("client.Id" in duo_param_xml and not duo_param_xml["client.Id"].text == new_client_id
      or "client.Secret" in duo_param_xml and not duo_param_xml["client.Secret"].text == new_secret
      or "host" in duo_param_xml and not duo_param_xml["host"].text == new_host
      or "redirecturi" in duo_param_xml and not duo_param_xml["redirecturi"].text == new_rediruri
      or "fail.Open" in duo_param_xml and not duo_param_xml["fail.Open"].text.lower() == str(new_failmode).lower()
      or not "fail.Open" in duo_param_xml):
        return True
    return False

def get_duo_params(root, new_client_id, new_secret, new_host, new_rediruri, new_failmode, filter_param, init_param):
    duo_param_name = {}
    for child in root.iter(filter_param):
        if child[0].text == "duoauth":
            duo_param_name["filter"] = child
            for duo_param_xml in child.findall(init_param):
                # We always have the first child of "init-param" be "param-name" and the second be "param-value"
                param_name = duo_param_xml[0]
                param_value = duo_param_xml[1]
                # We need to change the text from "ikey" to "client.Id" and "skey" to "client.Secret"
                if param_name.text == "ikey" or param_name.text == "skey":
                    duo_param_name[param_name.text] = [param_name, param_value]
                else:
                    duo_param_name[param_name.text] = param_value
            break
    return duo_param_name

def duoauth_xml_installed_version(duo_web_xml):
    plugin_xml_sdkversion = 0
    if "ikey" in duo_web_xml:
        plugin_xml_sdkversion = 2
    elif "client.Id" in duo_web_xml:
        plugin_xml_sdkversion = 4
    return plugin_xml_sdkversion

def duo_plugin_is_installed(lib_path):
    is_installed = False
    path = glob(os.path.join(lib_path, 'duo-filter-*.jar'))
    if len(path) != 0:
        debug("{path} already exists".format(path=path[0]))
        is_installed = True

    return is_installed

def install_jars(lib_path):
    files_to_install = get_files_to_install()
    if not files_to_install:
        fail(
            "ERROR: Unable to find files to install. Aborting installation. Does {file_location} exist and have the plugin jar?".format(
                file_location=os.path.join(SCRIPT_DIRECTORY, 'etc')
            )
        )
    remove_existing_duo_installation(lib_path)
    for f in files_to_install:
        debug("copying {src} to {dest}".format(src=f, dest=lib_path))
        copy2(f, lib_path)

def user_wants_upgrade():
    user_input = ''
    while user_input.lower() not in ['y', 'n']:
        user_input = input("Continue installing Duo (y/n)? ")

    return user_input.lower() == 'y'


class DefaultHelpParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)


def main():
    parser = DefaultHelpParser(
        epilog=textwrap.dedent("""
        Your Duo Jira/Confluence application's Client ID, Client Secret, and API Host can be found in your Duo account's Admin Panel at admin.duosecurity.com
        The redirect URL is the URL of the Jira/Confluence dashboard page after successful login.
        """),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )
    software_type = parser.add_mutually_exclusive_group(required=True)
    software_type.add_argument('--confluence', action='store_true', help="Set if plugin install is for Confluence.")
    software_type.add_argument('--jira', action='store_true', help="Set if plugin install is for Jira.")

    parser.add_argument('--directory', type=str, default="",
                        required=False, help="Software installation directory. By default /opt/atlassian/jira if Jira is specified. /opt/atlassian/conflunce if Confluence is specified.")
    parser.add_argument('-i', '--client-id', type=str, required=True, help="Duo integration key")
    parser.add_argument('-s', '--client-secret', type=str, required=True, help="Duo secret key")
    parser.add_argument('-h', '--api-host', metavar="API_HOST", type=str, required=True, help="Duo API hostname")
    parser.add_argument('--redirect-url', metavar="URL", type=str, required=True, help="Redirect URL where to redirect after authentication")
    parser.add_argument('--fail-closed', action='store_true', required=False, help="Set this flag if a failure to perform 2FA should prevent user access. The default is to allow access if the Duo service cannot be reached.")
    parser.add_argument('--verbose', action='store_true', required=False, help="Display filesystem activity")

    args = parser.parse_args()

    if args.verbose:
        global DEBUG
        DEBUG=True

    if args.directory:
        root_install_dir = os.path.join(args.directory)
    else:
        root_install_dir = ''

    if args.confluence:
        if not root_install_dir:
            root_install_dir = os.path.join(os.path.sep, 'opt', 'atlassian', 'confluence')
        lib_path = os.path.join(root_install_dir, 'confluence', 'WEB-INF', 'lib')
        web_xml_path = get_xml_path(root_install_dir, 'web.xml')
        backup_xml_path = get_xml_path(root_install_dir, 'web-backup-duo-{date}.xml'.format(date=time.strftime("%Y-%m-%d_%H-%M-%S", time.gmtime())))
        web_xml_tag_prefix = "{http://xmlns.jcp.org/xml/ns/javaee}"
        ET.register_namespace('', "http://xmlns.jcp.org/xml/ns/javaee")
        ET.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")
        ET.register_namespace('schemaLocation', "http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd")
    elif args.jira:
        if not root_install_dir:
            root_install_dir = os.path.join(os.path.sep, 'opt', 'atlassian', 'jira')
        lib_path = os.path.join(root_install_dir, 'atlassian-jira', 'WEB-INF', 'lib')
        web_xml_path = get_xml_path(root_install_dir, 'web.xml', True)
        backup_xml_path = get_xml_path(root_install_dir, 'web-backup-duo-{date}.xml'.format(date=time.strftime("%Y-%m-%d_%H-%M-%S", time.gmtime())), True)
        web_xml_tag_prefix = "{http://java.sun.com/xml/ns/javaee}"
        ET.register_namespace('', "http://java.sun.com/xml/ns/javaee")
        ET.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")
        ET.register_namespace('schemaLocation', "http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd")
    else:
        fail("Something went wrong setting the install path")

    filter_param = "{web_xml_prefix}filter".format(web_xml_prefix=web_xml_tag_prefix)
    filter_mapping_param = "{web_xml_prefix}filter-mapping".format(web_xml_prefix=web_xml_tag_prefix)
    init_param = "{web_xml_prefix}init-param".format(web_xml_prefix=web_xml_tag_prefix)
    filter_name_param = "{web_xml_prefix}filter-name".format(web_xml_prefix=web_xml_tag_prefix)
    if not valid_paths([root_install_dir, lib_path, web_xml_path]):
        fail("The directory {directory} does not look like a Jira or Confluence installation. Use the -d option to specify where your application is installed.".format(directory=str(root_install_dir)))

    try:
        xml_parser = ET.XMLParser(target=CommentedTreeBuilder())
        tree = ET.parse(web_xml_path, xml_parser)
    except:
        fail("Error parsing {web_xml_path}. Unable to install Duo Atlassian Plugin".format(web_xml_path=web_xml_path))
    root = tree.getroot()

    jars_exist = duo_plugin_is_installed(lib_path)
    duo_param_xml = get_duo_params(root, args.client_id, args.client_secret, args.api_host, args.redirect_url, (not args.fail_closed), filter_param, init_param)
    xml_existing_version = duoauth_xml_installed_version(duo_param_xml)
    if jars_exist:
        warn("Warning: It looks like the Duo plugin has already been installed previously.")

        if xml_existing_version == 0:
            warn("Warning: It looks like web.xml was never previously configured. Manual configuration will be required after upgrade.")
            warn("Continuing installation overwrites the current plugin version and will require manually updating web.xml.")
        if xml_existing_version == 2:
            warn("Warning: It looks like the Duo information in web.xml is using an older format and will be updated during the upgrade.")
            warn("Continuing installation overwrites the current plugin version and will update web.xml.")
        if xml_existing_version == 4:
            warn("Continuing installation overwrites the current plugin version and uses the existing application information in web.xml.")

        if not user_wants_upgrade():
            succeed("Exiting installation; no changes made.")

    info("Copying in Duo application files...")
    install_jars(lib_path)

    if xml_existing_version == 4:
        if need_update_xml_param(duo_param_xml, args.client_id, args.client_secret, args.api_host, args.redirect_url, (not args.fail_closed)):
            warn("Warning: We will be changing {web_xml}. We will back up your web.xml as {backup_xml}".format(web_xml=web_xml_path,
                                                                                                               backup_xml=backup_xml_path))
            warn("Continuing installation updates web.xml, stopping will require manual web.xml update.")
            duo_xml_string = duo_filter_xml.format(client_id=args.client_id, client_secret=args.client_secret,
                host=args.api_host, url=args.redirect_url,
                fail_open=(not args.fail_closed),
            )
            success_install_message = success_message_manual_websdk_4_update_xml.format(duo_xml_string=duo_xml_string,
                                    web_xml_path=web_xml_path, software='Jira' if args.jira else 'Confluence')
            if user_wants_upgrade():
                try:
                    os.rename(web_xml_path, backup_xml_path)
                    update_xml_websdk_4(duo_param_xml, args.client_id, args.client_secret, args.api_host, args.redirect_url, (not args.fail_closed))
                    tree.write(web_xml_path)
                    success_install_message = success_message_install_xml.format(web_xml_path=web_xml_path, software='Jira' if args.jira else 'Confluence')
                except:
                    os.rename(backup_xml_path, web_xml_path)
                    fail("\nError adding Duo Atlassian Plugin to {web_xml_path}, manual updates needed.{install_message}".format(web_xml_path=web_xml_path, install_message=success_install_message))
        else:
            success_install_message = success_message_no_xml_required.format(software='Jira' if args.jira else 'Confluence')
        succeed(success_install_message)
    if xml_existing_version == 2:
        warn("Warning: We will be changing {web_xml}. We will back up your web.xml as {backup_xml}".format(web_xml=web_xml_path,
                                                                                                           backup_xml=backup_xml_path))
        warn("Continuing installation updates web.xml, stopping will require manual web.xml update.")
        duo_xml_string = duo_filter_xml.format(client_id=args.client_id, client_secret=args.client_secret,
            host=args.api_host, url=args.redirect_url,
            fail_open=(not args.fail_closed),
        )
        success_upgrade_message = success_message_manual_upgrade_xml.format(duo_xml_string=duo_xml_string,
                                    filter_class='com.atlassian.jira.security.JiraSecurityFilter' if args.jira else 'com.atlassian.confluence.web.filter.ConfluenceSecurityFilter',
                                    web_xml_path=web_xml_path, software='Jira' if args.jira else 'Confluence')
        if user_wants_upgrade():
            try:
                copyfile(web_xml_path, backup_xml_path)
                update_xml_websdk_2(duo_param_xml, args.client_id, args.client_secret, args.api_host, args.redirect_url, (not args.fail_closed))
                tree.write(web_xml_path)
                success_upgrade_message = success_message_upgrade_xml.format(web_xml_path=web_xml_path,
                                            software='Jira' if args.jira else 'Confluence')
            except:
                os.rename(backup_xml_path, web_xml_path)
                fail("\nError adding Duo Atlassian Plugin to {web_xml_path}, manual updates needed.{install_message}".format(web_xml_path=web_xml_path, install_message=success_upgrade_message))

        succeed(success_upgrade_message)
    else:
        warn("Warning: We will be changing {web_xml}. We will back up your web.xml as {backup_xml}".format(web_xml=web_xml_path,
                                                                                                           backup_xml=backup_xml_path))
        warn("Continuing installation updates web.xml, stopping will require manual web.xml update.")
        duo_xml_string = duo_filter_xml.format(client_id=args.client_id, client_secret=args.client_secret,
            host=args.api_host, url=args.redirect_url,
            fail_open=(not args.fail_closed),
        )
        success_install_message = success_message_install_manual_xml.format(web_xml_path=web_xml_path, duo_xml_string=duo_xml_string,
            filter_class='com.atlassian.jira.security.JiraSecurityFilter' if args.jira else 'com.atlassian.confluence.web.filter.ConfluenceSecurityFilter',
            software='Jira' if args.jira else 'Confluence',
            )
        if user_wants_upgrade():
            try:
                copyfile(web_xml_path, backup_xml_path)
                duo_xml = ET.fromstring(duo_xml_string)
                duo_xml_mapping = ET.fromstring(duo_mapping_xml)
                security_filter = get_security_xml_location(root, filter_param, filter_name_param)
                root.insert(security_filter, duo_xml)
                security_mapping = get_security_xml_location(root, filter_mapping_param, filter_name_param)
                root.insert(security_mapping, duo_xml_mapping)
                tree.write(web_xml_path)

                success_install_message = success_message_install_xml.format(web_xml_path=web_xml_path,
                    software='Jira' if args.jira else 'Confluence',
                    )
            except:
                os.rename(backup_xml_path, web_xml_path)
                fail("\nError adding Duo Atlassian Plugin to {web_xml_path}, manual updates needed.{install_message}".format(web_xml_path=web_xml_path, install_message=success_install_message))

        succeed(success_install_message)


success_message_install_manual_xml = """
Duo jars have been installed.

** MANUAL STEPS REQUIRED TO FINISH INSTALLATION **
The DuoAuthFilter must be added to the web.xml configuration.
- Edit web.xml, located at {web_xml_path}.
- Locate the filter:
    <filter>
        <filter-name>security</filter-name>
        <filter-class>{filter_class}</filter-class>
    </filter>
- Add the following directly after the filter listed above:
{duo_xml_string}
- Locate the filter-mapping:
    <filter-mapping>
        <filter-name>security</filter-name>
        <url-pattern>/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
        <dispatcher>FORWARD</dispatcher> <!-- we want security to be applied after urlrewrites, for example -->
    </filter-mapping>
- Add the following directly after the filter-mapping listed above:
    <filter-mapping>
        <filter-name>duoauth</filter-name>
        <url-pattern>/*</url-pattern>
        <dispatcher>FORWARD</dispatcher>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>
- Restart {software}.
"""

success_message_upgrade_xml = """
Duo jars have been upgraded.
{web_xml_path} has been updated.

** MANUAL STEPS REQUIRED TO FINISH UPGRADE **
- Using the {software} web UI, uninstall the legacy "duo-twofactor" add-on/app. An app is no longer required for this plugin.
- Restart {software}.
"""

success_message_install_xml = """
Duo jars have been upgraded.
{web_xml_path} has been updated.

** MANUAL STEPS REQUIRED TO FINISH UPGRADE **
- Restart {software}.
"""

success_message_manual_websdk_4_update_xml = """
Duo jars have been upgraded.

 ** MANUAL STEPS REQUIRED TO FINISH UPGRADE **
Using the {software} web UI, uninstall the legacy "duo-twofactor" add-on/app. An app is no longer required for this plugin.

The DuoAuthFilter parameters have changed and must be updated:
- Edit web.xml, located at {web_xml_path}.
- Locate the existing Duo filter:
    <filter>
        <filter-name>duoauth</filter-name>
        <filter-class>com.duosecurity.seraph.filter.DuoAuthFilter</filter-class>
        ...
    </filter>
- Delete the existing filter and replace it with the following:
{duo_xml_string}
- Restart {software}.
"""
success_message_manual_upgrade_xml =  """
Duo jars have been upgraded.

 ** MANUAL STEPS REQUIRED TO FINISH UPGRADE **
Using the {software} web UI, uninstall the legacy "duo-twofactor" add-on/app. An app is no longer required for this plugin.

The DuoAuthFilter parameters have changed and must be updated:
- Edit web.xml, located at {web_xml_path}.
- Locate the existing Duo filter:
    <filter>
        <filter-name>duoauth</filter-name>
        <filter-class>com.duosecurity.seraph.filter.DuoAuthFilter</filter-class>
        ...
    </filter>
- Delete the existing filter and replace it with the following:
{duo_xml_string}
- Using the {software} web UI, uninstall the legacy "duo-twofactor" add-on/app. An app is no longer required for this plugin.
- Restart {software}.
"""

success_message_no_xml_required = """
Duo jars have been upgraded.
Restart {software} to complete upgrade.
"""

redirect_uri_str_xml = """        <init-param>
            <param-name>redirecturi</param-name>
            <param-value>{redirect_url}</param-value>
        </init-param>
"""

fail_mode_str_xml = """        <init-param>
            <param-name>fail.Open</param-name>
            <param-value>{fail_mode}</param-value>
        </init-param>
"""

duo_filter_xml = """    <filter>
        <filter-name>duoauth</filter-name>
        <filter-class>com.duosecurity.seraph.filter.DuoAuthFilter</filter-class>
        <init-param>
            <param-name>client.Id</param-name>
            <param-value>{client_id}</param-value>
        </init-param>
        <init-param>
            <param-name>client.Secret</param-name>
            <param-value>{client_secret}</param-value>
        </init-param>
        <init-param>
            <param-name>redirecturi</param-name>
            <param-value>{url}</param-value>
        </init-param>
        <init-param>
            <param-name>host</param-name>
            <param-value>{host}</param-value>
        </init-param>
        <init-param>
            <param-name>fail.Open</param-name>
            <param-value>{fail_open}</param-value>
        </init-param>
    </filter>
"""

duo_mapping_xml = """    <filter-mapping>
        <filter-name>duoauth</filter-name>
        <url-pattern>/*</url-pattern>
        <dispatcher>FORWARD</dispatcher>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>
"""

if __name__ == '__main__':
    main()
