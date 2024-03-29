# Deprecation Notice

This repository is deprecated by Duo Security, since Atlassian has [ended support](https://www.atlassian.com/migration/assess/journey-to-cloud) for the on-premises Jira and Confluence Server products.  The repository will remain public and visible, and integrations built using this repository's code will continue to work.  You can also continue to fork, clone, or pull from this repository.

However, Duo will not provide any further releases or enhancements.

For cloud-based Atlassian products, Duo recommends its [SSO](https://duo.com/docs/sso-atlassian-cloud) solution for multifactor authentication.

# Duo Atlassian Plugin
## Overview
[![Build Status](https://github.com/duosecurity/duo_universal_atlassian/actions/workflows/java-ci.yml/badge.svg)](https://github.com/duosecurity/duo_universal_atlassian/actions/workflows/java-ci.yml)
[![Issues](https://img.shields.io/github/issues/duosecurity/duo_universal_atlassian)](https://github.com/duosecurity/duo_universal_atlassian/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/duo_universal_atlassian)](https://github.com/duosecurity/duo_universal_atlassian/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/duo_universal_atlassian)](https://github.com/duosecurity/duo_universal_atlassian/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/duo_universal_atlassian/blob/master/LICENSE)

Duo two-factor authentication plugin for Jira and Confluence with Duo Universal Prompt .

## Compatibility Notes

- Certain Confluence plugin combinations can result in Jackson dependency conflicts with the duo_universal_atlassian plugin.
Please use [this modified release](https://github.com/jeffreyparker/duo_universal_atlassian/releases/tag/2.0.3.1) if you encounter jar dependency errors in Confluence.

- Confluence 7.14.1 and later include a significantly different and minimal `web.xml` file. For these versions, you can insert the Duo `<filter>` and `<filter-mapping>` sections *anywhere* within the main `web-app` block.

## Usage
Installation documents:
- Confluence: https://duo.com/docs/confluence
- Jira: https://duo.com/docs/jira

## TLS 1.2 and 1.3 Support

Duo_universal_atlassian uses the Java cryptography libraries for TLS operations. Both TLS 1.2 and 1.3 are supported by Java 8 and later versions.

## Development Prerequisites
The following are steps for the open source community to build and contribute to this plugin.
 - Install the [Atlassian SDK](https://developer.atlassian.com/server/framework/atlassian-sdk/install-the-atlassian-sdk-on-a-linux-or-mac-system/)
 - A working Java environment (Tested with Java 8)
 - The Duo Universal Prompt repository for the Java language [`duo_universal_java`](https://github.com/duosecurity/duo_universal_java)

## Development Installation

- Inside of duo_universal_java run `atlas-mvn clean install`
- Inside of duo_atlassian_plugin run `atlas-mvn package`
- For Jira Development
  - Copy duo_seraph_filter/target/duo-filter-$VERSION-jar-with-dependencies.jar to $JIRA_DIR/atlassian-jira/WEB-INF/lib/
  - Restart Jira `sudo /etc/init.d/jira stop ; sudo /etc/init.d/jira start`
- For Confluence Development
  - Copy duo_seraph_filter/target/duo-filter-$VERSION-jar-with-dependencies.jar to $CONFLUENCE_DIR/confluence/WEB-INF/lib/
  - Restart Confluence `sudo /etc/init.d/confluence stop ; sudo /etc/init.d/confluence start`

## Automated Testing

From inside of duo_atlassian_plugin run:

`atlas-mvn test`

## Linting

From inside of duo_atlassian_plugin run:

`atlas-mvn checkstyle:check`

# Support

Please report any bugs, feature requests, or issues to us directly at support@duosecurity.com.

Have fun!

http://www.duosecurity.com/

