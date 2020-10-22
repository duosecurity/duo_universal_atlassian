# Duo Atlassian Plugin
## Overview

Duo two-factor authentication plugin for Jira and Confluence with Duo Universal Prompt .

## Usage
Installation documents:
- Confluence: https://duo.com/docs/confluence-universal
- Jira: https://duo.com/docs/jira-universal

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

