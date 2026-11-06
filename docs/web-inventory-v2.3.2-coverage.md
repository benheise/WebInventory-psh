# WebInventory v2.3.2 — version coverage by product

Every product (kind + name, as the rules name it) whose rules carry an NVD CPE but whose detection rules capture no
version, with what v2.3.2 does about it. Products whose detection rules capture a version are not listed. Generated
by `tools/version/coverage.py --md`; CVE and KEV counts are the NVD/KEV entries naming the product's CPE (NVD feeds
2002–2026 and the CISA KEV catalog used for v2.3.1's validation).

| Status | Meaning |
|---|---|
| version-only | a version-only rule reads its version (rule ids; evidence: container, source, sample, wordpress, library) |
| fixed only | a rule writes a version in (e.g. a favicon's range); no rule reads one |
| same CPE captured | no rule for this name reads a version, but a rule for another product with the same CPE does (often on another service, e.g. an SNMP sysDescr) |
| platform | a general-purpose operating system: the patch level is not visible remotely |
| hardware | a hardware CPE: NVD gives hardware no software version |
| hidden | checked: the responses a scan receives carry no version |
| other-url | the version is only at another URL (an API or a file); the tool sends no extra request for a version |
| coarse | only a major or major.minor is visible where releases have more parts |
| not-version | the number visible is not the release (a build hash or number, a cache-buster, a component version) |
| no-known-location | none of WhatWeb (passive plugins), nuclei-templates (detection templates), Recog or webappanalyzer extracts a version for it, and none was found |
| unverified | a database has a candidate, but no image of the product or sample of the response exists to check it against |
| unreviewed | one of those databases has a candidate that was not verified yet |

## Summary

```
products with a CPE: 1327
  with a version before version-only rules (captured or fixed): 598
  with a version now (captured, fixed or version-only): 690
  captured           582
  no-known-location  390
  version-only       92
  hidden             87
  not-version        42
  same CPE captured  31
  hardware           30
  other-url          27
  platform           21
  fixed only         16
  coarse             7
  unverified         2
still without a version: 637 products, 601 with NVD CVEs, 137 with KEV entries
```

## Products

| Product | Kind | CPE | CVEs | KEV | Version | Rule or reason |
|---|---|---|---:|---:|---|---|
| Microsoft Windows Server 2019 | os | o:microsoft:windows_server_2019 | 6437 | 159 | platform |  |
| Microsoft Windows Server 2016 | os | o:microsoft:windows_server_2016 | 6382 | 157 | platform |  |
| Microsoft Windows Server 2008 Datacenter Edition | os | o:microsoft:windows_server_2008 | 3552 | 148 | fixed only |  |
| Microsoft Windows Server 2008 R2, Datacenter Edition | os | o:microsoft:windows_server_2008 | 3552 | 148 | fixed only |  |
| Microsoft Windows 8.1 | os | o:microsoft:windows_8.1 | 2215 | 94 | platform |  |
| Fedora | os | o:fedoraproject:fedora | 5361 | 88 | platform |  |
| Apple Mac OS | os | o:apple:macos | 3195 | 70 | platform |  |
| Ubuntu | os | o:canonical:ubuntu_linux | 4121 | 47 | same CPE captured |  |
| Cisco IOS | service | o:cisco:ios | 617 | 39 | fixed only |  |
| Red Hat Enterprise Linux | os | o:redhat:enterprise_linux | 1956 | 28 | fixed only |  |
| Google Android | os | o:google:android | 8366 | 21 | platform |  |
| Fortinet FortiOS | service | o:fortinet:fortios | 276 | 21 | hidden | login pages (/, /remote/login) carry no version; build only in authenticated API |
| Fortinet FortiOS | os | o:fortinet:fortios | 276 | 21 | hidden | login pages (/, /remote/login) carry no version; build only in authenticated API |
| Microsoft Exchange 2007 Server | service | a:microsoft:exchange_server | 259 | 20 | version-only | v:exchange2007-imap (sample), v:exchange2007-pop3 (sample) |
| Microsoft Windows Server 2003, Datacenter Edition | os | o:microsoft:windows_server_2003 | 455 | 17 | same CPE captured |  |
| Adobe ColdFusion | service | a:adobe:coldfusion | 296 | 17 | hidden | no version in default responses |
| Palo Alto GlobalProtect | service | o:paloaltonetworks:pan-os | 238 | 17 | hidden | see PAN-OS |
| Palo Alto Networks PAN-OS | service | o:paloaltonetworks:pan-os | 238 | 17 | hidden | GlobalProtect/management pages carry no version (only ETag/Last-Modified dates, a lookup table) |
| Palo Alto Networks PAN-OS | os | o:paloaltonetworks:pan-os | 238 | 17 | hidden | GlobalProtect/management pages carry no version (only ETag/Last-Modified dates, a lookup table) |
| Microsoft Windows 8 | os | o:microsoft:windows_8 | 254 | 16 | platform |  |
| Ivanti Connect Secure | service | a:ivanti:connect_secure | 132 | 16 | same CPE captured |  |
| Cisco ASA | service | o:cisco:adaptive_security_appliance_software | 341 | 15 | same CPE captured |  |
| Java | service | a:oracle:jre | 817 | 14 | not-version | X-Powered-By JSP/2.3 is the JSP specification, not the JRE |
| F5 BIG-IP APM | service | a:f5:big-ip_access_policy_manager | 630 | 13 | hidden | see F5 BIG-IP |
| Citrix Gateway | service | a:citrix:netscaler_gateway | 41 | 13 | not-version | only resource hashes (?v=<md5>), a lookup table |
| Citrix NetScaler Gateway | service | a:citrix:netscaler_gateway | 41 | 13 | not-version | see Citrix Gateway |
| Citrix NetScaler ADC | service | a:citrix:netscaler_application_delivery_controller | 34 | 13 | hidden | no version in default responses |
| VMware vCenter | service | a:vmware:vcenter_server | 81 | 12 | other-url | see VMware vCenter Server |
| VMware vCenter Server | service | a:vmware:vcenter_server | 81 | 12 | other-url | only via the SOAP /sdk RetrieveServiceContent call |
| F5 Advanced WAF (ASM) | service | a:f5:big-ip_application_security_manager | 580 | 11 | hidden | see F5 BIG-IP |
| F5 BIG-IP | service | a:f5:big-ip_local_traffic_manager | 541 | 11 | hidden | TMUI/APM pages carry no version |
| F5 BIG-IP LTM | service | a:f5:big-ip_local_traffic_manager | 541 | 11 | hidden | see F5 BIG-IP |
| RoundCube | service | a:roundcube:webmail | 107 | 11 | version-only | v:roundcube (container) |
| Roundcube Webmail | service | a:roundcube:webmail | 107 | 11 | fixed only |  |
| VMware ESXi | service | o:vmware:esxi | 117 | 9 | same CPE captured |  |
| Juniper J-Web | service | o:juniper:junos | 793 | 8 | same CPE captured |  |
| Drupal CMS | service | a:drupal:drupal | 279 | 8 | fixed only |  |
| QNAP QTS | service | o:qnap:qts | 283 | 7 | other-url | /cgi-bin/authLogin.cgi |
| QNAP QTS | os | o:qnap:qts | 283 | 7 | other-url | /cgi-bin/authLogin.cgi |
| GitLab | service | a:gitlab:gitlab | 1507 | 6 | hidden | sign-in page carries a git revision, not the release; /help needs a login |
| Microsoft Windows 2000 | os | o:microsoft:windows_2000 | 514 | 6 | platform |  |
| Microsoft Windows 2000 Datacenter Server | os | o:microsoft:windows_2000 | 514 | 6 | platform |  |
| Microsoft Windows 2000 Server | os | o:microsoft:windows_2000 | 514 | 6 | platform |  |
| Plex Media Server | service | a:plex:media_server | 19 | 5 | other-url | /identity; X-Plex-Protocol is the protocol version |
| N-able N-central | service | a:n-able:n-central | 15 | 5 | other-url | the page at / is a script redirect; the version is on /login |
| JetBrains TeamCity | service | a:jetbrains:teamcity | 283 | 4 | version-only | v:teamcity-maintenance (container), v:teamcity (sample) |
| Cisco ISE | service | a:cisco:identity_services_engine | 188 | 4 | not-version | ?_isever=<build timestamp> |
| Craft CMS | service | a:craftcms:craft_cms | 97 | 4 | hidden | X-Powered-By: Craft CMS, no version |
| WatchGuard Firebox | service | o:watchguard:fireware | 75 | 4 | hidden | no version on the login page |
| WatchGuard Fireware | os | o:watchguard:fireware | 75 | 4 | no-known-location |  |
| ManageEngine ServiceDesk Plus | service | a:zohocorp:manageengine_servicedesk_plus | 50 | 4 | not-version | login assets carry the build number; NVD needs release + build, which no response gives |
| Veeam Backup & Replication | service | a:veeam:veeam_backup_&_replication | 42 | 4 | hidden | no version on the web console login |
| Citrix NetScaler Gateway | os | o:citrix:netscaler_gateway_firmware | 31 | 4 | not-version | see Citrix Gateway |
| Citrix Netscaler Gateway Firmware | os | o:citrix:netscaler_gateway_firmware | 31 | 4 | no-known-location |  |
| Zyxel USG20-VPN firmware | os | o:zyxel:usg20-vpn_firmware | 15 | 4 | no-known-location |  |
| Oracle Fusion Middleware | service | a:oracle:fusion_middleware | 313 | 3 | coarse | welcome page names the generation (11g/12c), not the release |
| Cisco Unified Communications Manager | service | a:cisco:unified_communications_manager | 239 | 3 | other-url | /cucm-uds/version |
| Ruby on Rails | service | a:rubyonrails:rails | 118 | 3 | version-only | v:rails (source) |
| DNN | service | a:dnnsoftware:dotnetnuke | 76 | 3 | not-version | only ?cdv= client-dependency counters |
| Apache ActiveMQ | service | a:apache:activemq | 75 | 3 | other-url | the console start page (/) is static; the version is on /admin/ (authenticated) or hawtconfig.json (Artemis) |
| SonicWall SonicOS | service | o:sonicwall:sonicos | 68 | 3 | same CPE captured |  |
| Couchbase Server | service | a:couchbase:couchbase_server | 63 | 3 | hidden | container couchbase 7.6.12: / redirects to /ui/index.html, which carries no version |
| ManageEngine ADSelfService Plus | service | a:zohocorp:manageengine_adselfservice_plus | 51 | 3 | not-version | see ManageEngine ServiceDesk Plus |
| Apache Solr | service | a:apache:solr | 47 | 3 | version-only | v:solr (container) |
| Oracle Transportation Management | service | a:oracle:transportation_management | 31 | 3 | no-known-location |  |
| Sitecore | service | a:sitecore:experience_platform | 21 | 3 | other-url | /sitecore/shell/sitecore.version.xml |
| CrushFTP | service | a:crushftp:crushftp | 17 | 3 | coarse | old Server headers gave "Version 6.5"; NVD numbers builds 11.3.7_69 |
| CrushFTP Web Interface | service | a:crushftp:crushftp | 17 | 3 | coarse | see CrushFTP |
| Microsoft Windows 10 | os | o:microsoft:windows_10 | 2974 | 2 | platform |  |
| Oracle PeopleSoft | service | a:oracle:peoplesoft_enterprise_peopletools | 447 | 2 | not-version | only copyright years |
| Joomla! | service | a:joomla:joomla! | 340 | 2 | same CPE captured |  |
| Splunk | service | a:splunk:splunk | 298 | 2 | version-only | v:splunk (sample) |
| Splunkd | service | a:splunk:splunk | 298 | 2 | same CPE captured |  |
| Cisco NX-OS | os | o:cisco:nx-os | 275 | 2 | no-known-location |  |
| Microsoft Windows NT | os | o:microsoft:windows_nt | 252 | 2 | fixed only |  |
| Microsoft Windows NT Server | os | o:microsoft:windows_nt | 252 | 2 | fixed only |  |
| Apache Airflow | service | a:apache:airflow | 158 | 2 | hidden | airflow/www/templates/airflow/main.html prints the version in the footer only when logged in |
| Red Hat OpenShift | service | a:redhat:openshift | 145 | 2 | no-known-location |  |
| Envoy | service | a:envoyproxy:envoy | 127 | 2 | hidden | server: envoy, no version |
| Zabbix | service | a:zabbix:zabbix | 115 | 2 | hidden | ui/include/views/general.login.php renders makePageFooter(false): the login page footer has no version |
| WSO2 API Manager | service | a:wso2:api_manager | 95 | 2 | hidden | Server: WSO2 Carbon Server, no version |
| Elastic Search | service | a:elastic:elasticsearch | 91 | 2 | same CPE captured |  |
| Control Web Panel | service | a:control-webpanel:webpanel | 85 | 2 | no-known-location |  |
| Progress WhatsUp Gold | service | a:progress:whatsup_gold | 62 | 2 | no-known-location |  |
| Oracle Access Manager | service | a:oracle:access_manager | 53 | 2 | version-only | v:oam-footer (sample) |
| ManageEngine Endpoint Central | service | a:zohocorp:manageengine_desktop_central | 48 | 2 | not-version | see ManageEngine ServiceDesk Plus |
| Tenable.sc | service | a:tenable:tenable.sc | 46 | 2 | no-known-location |  |
| ASP.NET Core | service | a:microsoft:asp.net_core | 41 | 2 | hidden |  |
| PRTG Network Monitor | service | a:paessler:prtg_network_monitor | 39 | 2 | version-only | v:prtg-server (sample), v:prtg-css (sample) |
| ManageEngine SupportCenter Plus | service | a:zohocorp:manageengine_supportcenter_plus | 31 | 2 | not-version | see ManageEngine ServiceDesk Plus |
| Istio | service | a:istio:istio | 29 | 2 | hidden | see Envoy |
| ManageEngine ServiceDesk Plus MSP | service | a:zohocorp:manageengine_servicedesk_plus_msp | 26 | 2 | not-version | see ManageEngine ServiceDesk Plus |
| Metabase | service | a:metabase:metabase | 26 | 2 | version-only | v:metabase (container) |
| MinIO | service | a:minio:minio | 23 | 2 | hidden | Server: MinIO, no version |
| ManageEngine Password Manager Pro | service | a:zohocorp:manageengine_password_manager_pro | 22 | 2 | not-version | see ManageEngine ServiceDesk Plus |
| Wing FTP Server | service | a:wftpserver:wing_ftp_server | 20 | 2 | version-only | v:wingftp (sample) |
| ManageEngine PAM360 | service | a:zohocorp:manageengine_pam360 | 14 | 2 | not-version | see ManageEngine ServiceDesk Plus |
| GoAnywhere | service | a:fortra:goanywhere_managed_file_transfer | 13 | 2 | same CPE captured |  |
| ManageEngine Access Manager Plus | service | a:zohocorp:manageengine_access_manager_plus | 11 | 2 | not-version | see ManageEngine ServiceDesk Plus |
| Commerce Server | service | a:microsoft:commerce_server | 9 | 2 | hidden |  |
| Microsoft Commerce Server | service | a:microsoft:commerce_server | 9 | 2 | hidden |  |
| Zyxel USG40 firmware | os | o:zyxel:usg40_firmware | 9 | 2 | no-known-location |  |
| Zyxel USG60 firmware | os | o:zyxel:usg60_firmware | 9 | 2 | no-known-location |  |
| Sophos Firewall | service | o:sophos:sfos | 8 | 2 | unverified | nuclei sophos-fw-version-detect reads typography.css?version= on login.jsp; no image or sample of the value, and NVD numbers SFOS by release and MR update (17.5 maintenance_release9) |
| Check Point Gaia | service | o:checkpoint:gaia_os | 6 | 2 | no-known-location |  |
| Check Point GAiA OS | os | o:checkpoint:gaia_os | 6 | 2 | no-known-location |  |
| WebSphere | service | a:ibm:websphere_application_server | 503 | 1 | same CPE captured |  |
| XWiki | service | a:xwiki:xwiki | 248 | 1 | version-only | v:xwiki-webjar (container), v:xwiki-footer (sample) |
| Elastic Kibana | service | a:elastic:kibana | 189 | 1 | version-only | v:kibana (source) |
| MongoDB | service | a:mongodb:mongodb | 188 | 1 | hidden | the HTTP-on-driver-port text carries no version |
| n8n | service | a:n8n:n8n | 179 | 1 | version-only | v:n8n (container) |
| Cacti | service | a:cacti:cacti | 152 | 1 | fixed only |  |
| Aruba Networks ClearPass Policy Manager | service | a:arubanetworks:clearpass_policy_manager | 136 | 1 | no-known-location |  |
| Synology DSM | service | o:synology:diskstation_manager | 94 | 1 | no-known-location |  |
| Spring | service | a:vmware:spring_framework | 83 | 1 | hidden |  |
| WSO2 Identity Server | service | a:wso2:identity_server | 83 | 1 | hidden | no version in current releases |
| Traefik | service | a:traefik:traefik | 82 | 1 | hidden | container traefik v2.11.61, v3.7.17: / redirects to /dashboard/, whose HTML carries no version (only the API does) |
| Traefik Proxy | service | a:traefik:traefik | 82 | 1 | hidden | see Traefik |
| MLflow | service | a:lfprojects:mlflow | 77 | 1 | no-known-location |  |
| Wazuh | service | a:wazuh:wazuh | 73 | 1 | version-only | v:wazuh (sample) |
| Apache Superset | service | a:apache:superset | 70 | 1 | version-only | v:superset (sample) |
| dotCMS | service | a:dotcms:dotcms | 57 | 1 | no-known-location |  |
| October CMS | service | a:octobercms:october | 57 | 1 | no-known-location |  |
| Pulse Connect Secure | service | a:pulsesecure:pulse_connect_secure | 57 | 1 | other-url | see Ivanti Connect Secure |
| Pulse Secure | service | a:pulsesecure:pulse_connect_secure | 57 | 1 | other-url | see Ivanti Connect Secure |
| Atlassian Fisheye | service | a:atlassian:fisheye | 53 | 1 | same CPE captured |  |
| ManageEngine ADManager Plus | service | a:zohocorp:manageengine_admanager_plus | 53 | 1 | not-version | see ManageEngine ServiceDesk Plus |
| ManageEngine ADAudit Plus | service | a:zohocorp:manageengine_adaudit_plus | 52 | 1 | not-version | see ManageEngine ServiceDesk Plus |
| Progress MOVEit Transfer | service | a:progress:moveit_transfer | 49 | 1 | same CPE captured |  |
| SolarWinds Orion | service | a:solarwinds:orion_platform | 49 | 1 | no-known-location |  |
| SolarWinds Orion Platform | service | a:solarwinds:orion_platform | 49 | 1 | no-known-location |  |
| Tor | service | a:torproject:tor | 48 | 1 | no-known-location |  |
| Redis | service | a:redis:redis | 46 | 1 | hidden | -NOAUTH/-ERR replies carry no version |
| Strapi | service | a:strapi:strapi | 39 | 1 | hidden | X-Powered-By: Strapi <strapi.io> |
| Ignite Realtime OpenFire | service | a:igniterealtime:openfire | 37 | 1 | version-only | v:openfire (source) |
| Oracle Secure Global Desktop | service | a:oracle:secure_global_desktop | 33 | 1 | no-known-location |  |
| WSO2 Enterprise Integrator | service | a:wso2:enterprise_integrator | 33 | 1 | no-known-location |  |
| Cisco PIX | os | o:cisco:pix_firewall_software | 28 | 1 | fixed only |  |
| Progress WS_FTP | service | a:progress:ws_ftp_server | 28 | 1 | hidden | the web client carries none (the SSH banner of the same server does, on another port) |
| ThinkPHP | service | a:thinkphp:thinkphp | 27 | 1 | hidden | X-Powered-By: ThinkPHP, no version |
| ManageEngine AssetExplorer | service | a:zohocorp:manageengine_assetexplorer | 26 | 1 | not-version | see ManageEngine ServiceDesk Plus |
| Apache Spark | service | a:apache:spark | 23 | 1 | version-only | v:spark (container) |
| Caddy | service | a:caddyserver:caddy | 20 | 1 | hidden | Server: Caddy, no version |
| Yii | service | a:yiiframework:yii | 19 | 1 | hidden |  |
| SAP Commerce Cloud | service | a:sap:commerce_cloud | 18 | 1 | no-known-location |  |
| Atlassian Jira Service Management | service | a:atlassian:jira_service_management | 17 | 1 | not-version | ajs-version-number is the Jira platform version, not the JSM release |
| EmbedThis GoAhead Webserver | service | a:embedthis:goahead | 17 | 1 | no-known-location |  |
| GoAhead | service | a:embedthis:goahead | 17 | 1 | no-known-location |  |
| Cisco Expressway | service | a:cisco:expressway | 14 | 1 | hidden | login page names the edition, not the release |
| Varnish Cache | service | a:varnish_cache_project:varnish_cache | 14 | 1 | coarse | Via: 1.1 varnish (Varnish/6.6) gives major.minor only |
| Laravel | service | a:laravel:laravel | 10 | 1 | version-only | v:laravel (source) |
| Facebook Proxygen | service | a:facebook:proxygen | 7 | 1 | hidden |  |
| ManageEngine Analytics Plus | service | a:zohocorp:manageengine_analytics_plus | 7 | 1 | not-version | see ManageEngine ServiceDesk Plus |
| FatPipe Networks IPVPN Firmware | os | o:fatpipeinc:ipvpn_firmware | 6 | 1 | no-known-location |  |
| FatPipe Networks MPVPN Firmware | os | o:fatpipeinc:mpvpn_firmware | 6 | 1 | no-known-location |  |
| FatPipe Networks WARP Firmware | os | o:fatpipeinc:warp_firmware | 6 | 1 | no-known-location |  |
| cPanel WHM | service | a:cpanel:whm | 5 | 1 | no-known-location |  |
| mongo-express | service | a:mongo-express_project:mongo-express | 5 | 1 | no-known-location |  |
| Apache Flink | service | a:apache:flink | 4 | 1 | other-url | the REST API /config |
| CentOS | os | o:centos:centos | 4 | 1 | fixed only |  |
| Livewire | service | a:laravel:livewire | 4 | 1 | not-version | livewire.js?id=<hash> |
| Citrix StoreFront | service | a:citrix:storefront_server | 3 | 1 | no-known-location |  |
| ManageEngine AD360 | service | a:zohocorp:manageengine_ad360 | 3 | 1 | not-version | see ManageEngine ServiceDesk Plus |
| OpenBSD OpenSMTPD | service | a:openbsd:opensmtpd | 3 | 1 | hidden | banner says "ESMTP OpenSMTPD" |
| SolarWinds Virtualization Manager | service | a:solarwinds:virtualization_manager | 3 | 1 | no-known-location |  |
| Sangoma Switchvox | service | a:sangoma:switchvox | 2 | 1 | no-known-location |  |
| Adobe Experience Manager | service | a:adobe:experience_manager | 1290 | 0 | no-known-location |  |
| Adobe Experience Manager Edge Delivery Services | service | a:adobe:experience_manager | 1290 | 0 | no-known-location |  |
| Adobe Experience Manager Franklin | service | a:adobe:experience_manager | 1290 | 0 | no-known-location |  |
| Moodle | service | a:moodle:moodle | 637 | 0 | version-only | v:moodle-footer (sample) |
| Mattermost | service | a:mattermost:mattermost_server | 501 | 0 | version-only | v:mattermost (container) |
| Red Hat | os | o:redhat:linux | 229 | 0 | platform | Red Hat Enterprise Linux from a Server token |
| Red Hat Linux | os | o:redhat:linux | 229 | 0 | fixed only |  |
| TYPO3 CMS | service | a:typo3:typo3 | 218 | 0 | same CPE captured |  |
| PostgreSQL | service | a:postgresql:postgresql | 203 | 0 | hidden | startup error carries no version |
| Nextcloud | service | a:nextcloud:nextcloud, a:nextcloud:nextcloud_server | 189 | 0 | version-only | v:nextcloud (container) |
| Nextcloud Server | service | a:nextcloud:nextcloud_server | 189 | 0 | same CPE captured |  |
| SGI Irix | os | o:sgi:irix | 182 | 0 | same CPE captured |  |
| NetBSD | os | o:netbsd:netbsd | 168 | 0 | platform |  |
| DedeCMS | service | a:dedecms:dedecms | 165 | 0 | no-known-location |  |
| CMS Made Simple | service | a:cmsmadesimple:cms_made_simple | 154 | 0 | version-only | v:cmsms (sample) |
| Siebel CRM | service | a:oracle:siebel_crm | 154 | 0 | no-known-location |  |
| Mozilla Bugzilla | service | a:mozilla:bugzilla | 145 | 0 | version-only | v:bugzilla (source) |
| MyBB | service | a:mybb:mybb | 140 | 0 | not-version | general.js?ver= comes from the theme template, not the installed release |
| Gentoo | os | o:gentoo:linux | 136 | 0 | platform |  |
| Gentoo Linux | os | o:gentoo:linux | 136 | 0 | platform |  |
| Pimcore | service | a:pimcore:pimcore | 127 | 0 | no-known-location |  |
| HCL Digital Experience | service | a:ibm:websphere_portal | 126 | 0 | no-known-location |  |
| ownCloud | service | a:owncloud:owncloud | 116 | 0 | not-version | login page assets carry content hashes (container owncloud/server 10.16.7) |
| ownCloud Server | service | a:owncloud:owncloud | 116 | 0 | not-version | see ownCloud |
| Microweber | service | a:microweber:microweber | 114 | 0 | no-known-location |  |
| Checkmk | service | a:checkmk:checkmk | 108 | 0 | version-only | v:checkmk (container) |
| LibreNMS | service | a:librenms:librenms | 106 | 0 | no-known-location |  |
| SalesAgility SuiteCRM | service | a:salesagility:suitecrm | 105 | 0 | no-known-location |  |
| SuiteCRM | service | a:salesagility:suitecrm | 105 | 0 | no-known-location |  |
| Piwigo | service | a:piwigo:piwigo | 103 | 0 | version-only | v:piwigo (source) |
| Plone | service | a:plone:plone | 103 | 0 | no-known-location |  |
| Keycloak | service | a:redhat:keycloak | 98 | 0 | not-version | container quay.io/keycloak/keycloak 26.6: / redirects to the admin console, whose resources carry a random resourceVersion |
| PrestaShop | service | a:prestashop:prestashop | 93 | 0 | other-url | only on the back-office login, whose path is random per shop |
| Puppet Enterprise | service | a:puppet:puppet_enterprise | 89 | 0 | no-known-location |  |
| Symfony | service | a:sensiolabs:symfony | 89 | 0 | version-only | v:symfony (source) |
| HCL Domino | service | a:ibm:lotus_domino | 86 | 0 | same CPE captured |  |
| Lotus Domino | service | a:ibm:lotus_domino | 86 | 0 | fixed only |  |
| Lotus-Domino | service | a:ibm:lotus_domino | 86 | 0 | same CPE captured |  |
| McAfee ePolicy Orchestrator | service | a:mcafee:epolicy_orchestrator | 86 | 0 | hidden | the agent port this detection comes from carries none |
| LimeSurvey | service | a:limesurvey:limesurvey | 82 | 0 | no-known-location |  |
| IBM DataPower | service | a:ibm:datapower_gateway | 81 | 0 | no-known-location |  |
| IBM DataPower Gateway | service | a:ibm:datapower_gateway | 81 | 0 | no-known-location |  |
| osCommerce | service | a:oscommerce:oscommerce | 78 | 0 | no-known-location | the one candidate (nuclei oscommerce-detect) is a generic "osCommerce <n>" body match; the default catalog footer prints no version |
| e107 | service | a:e107:e107 | 77 | 0 | no-known-location |  |
| EyouCMS | service | a:eyoucms:eyoucms | 75 | 0 | no-known-location |  |
| Tiki Wiki CMS Groupware | service | a:tiki:tikiwiki_cms/groupware | 74 | 0 | no-known-location |  |
| Cisco Wireless LAN Controller | os | o:cisco:wireless_lan_controller_software | 73 | 0 | hidden |  |
| HashiCorp Vault | service | a:hashicorp:vault | 72 | 0 | hidden | container hashicorp/vault 1.20.4, 2.2.1: /ui/ carries no version (only /v1/sys/health) |
| Dovecot | service | a:dovecot:dovecot | 69 | 0 | hidden | banner says "Dovecot ready." |
| Tenable Nessus | service | a:tenable:nessus | 68 | 0 | no-known-location |  |
| Google Chrome OS | os | o:google:chrome_os | 67 | 0 | platform |  |
| Trustix Secure Linux | os | o:trustix:secure_linux | 65 | 0 | platform |  |
| Silverstripe | service | a:silverstripe:silverstripe | 64 | 0 | coarse | generator "SilverStripe 2.4" on 2.x, none since |
| Conectiva Linux | os | o:conectiva:linux | 63 | 0 | platform |  |
| Rocket.Chat | service | a:rocket.chat:rocket.chat | 62 | 0 | no-known-location |  |
| Apache NiFi | service | a:apache:nifi | 59 | 0 | no-known-location |  |
| Directus | service | a:monospace:directus | 56 | 0 | no-known-location |  |
| Kubernetes API | service | a:kubernetes:kubernetes | 56 | 0 | version-only | v:k8s-version (source) |
| ManageEngine OpManager | service | a:zohocorp:manageengine_opmanager | 56 | 0 | not-version | see ManageEngine ServiceDesk Plus |
| Essential Addons for Elementor | service | a:wpdeveloper:essential_addons_for_elementor | 55 | 0 | version-only | v:wp-essential-addons (wordpress) |
| Microsoft Windows Media Player | service | a:microsoft:windows_media_player | 53 | 0 | no-known-location |  |
| Odoo | service | a:odoo:odoo | 53 | 0 | other-url | POST /web/webclient/version_info |
| MailEnable | service | a:mailenable:mailenable | 50 | 0 | same CPE captured |  |
| Redmine | service | a:redmine:redmine | 50 | 0 | hidden | container redmine 6.0.12, 7.0.3: "Powered by Redmine" without version |
| Frappe | service | a:frappe:frappe | 49 | 0 | no-known-location |  |
| IBM Tivoli Storage Manager | service | a:ibm:tivoli_storage_manager | 49 | 0 | no-known-location |  |
| Netgate pfSense | service | a:netgate:pfsense | 49 | 0 | not-version | pfSense.js?v=<hash> |
| Mailman | service | a:gnu:mailman | 47 | 0 | other-url | Mailman 2 prints it on /mailman/listinfo pages, not on / |
| Microsoft Windows 95 | os | o:microsoft:windows_95 | 46 | 0 | platform |  |
| pgAdmin | service | a:pgadmin:pgadmin_4 | 46 | 0 | version-only | v:pgadmin (container) |
| osTicket | service | a:enhancesoft:osticket | 45 | 0 | hidden | only the installer page names the release |
| Check Point Firewall-1 | service | a:checkpoint:firewall-1 | 43 | 0 | no-known-location |  |
| Pligg | service | a:pligg:pligg_cms | 43 | 0 | no-known-location |  |
| XOOPS | service | a:xoops:xoops | 43 | 0 | no-known-location |  |
| Bludit | service | a:bludit:bludit | 42 | 0 | version-only | v:bludit (source) |
| Mastodon | service | a:joinmastodon:mastodon | 42 | 0 | version-only | v:mastodon (source) |
| Kirby | service | a:getkirby:kirby | 41 | 0 | no-known-location |  |
| Movable Type | service | a:sixapart:movable_type | 41 | 0 | version-only | v:movabletype (sample) |
| Symantec Endpoint Protection Manager | service | a:symantec:endpoint_protection_manager | 41 | 0 | no-known-location |  |
| CodeIgniter | service | a:codeigniter:codeigniter | 40 | 0 | fixed only |  |
| EspoCRM | service | a:espocrm:espocrm | 40 | 0 | no-known-location |  |
| Zulip | service | a:zulip:zulip_server | 40 | 0 | no-known-location |  |
| OpenCart | service | a:opencart:opencart | 39 | 0 | version-only | v:opencart-footer (sample) |
| phpBB | service | a:phpbb:phpbb | 38 | 0 | coarse | phpBB 3 prints none; cookies give the major only |
| Nagios | service | a:nagios:nagios | 37 | 0 | no-known-location |  |
| Ruby Rack | service | a:rack:rack | 37 | 0 | hidden |  |
| HAProxy | service | a:haproxy:haproxy | 36 | 0 | hidden |  |
| HashiCorp Nomad | service | a:hashicorp:nomad | 36 | 0 | hidden | container hashicorp/nomad 1.10.5 (server agent): / redirects to /ui/, whose HTML and Ember config meta carry no version (only the HTTP API does) |
| OPNsense | service | a:opnsense:opnsense | 36 | 0 | no-known-location |  |
| OPNSense | service | a:opnsense:opnsense | 36 | 0 | no-known-location |  |
| Rancher | service | a:suse:rancher | 36 | 0 | unverified | container rancher/rancher v2.15.3 does not start in the lab (its embedded Kubernetes needs cgroup v2); the one candidate (nuclei rancher-panel: <!-- x.y.z --> in the older Ember UI, whose static title is "Loading") is not on the page the Rancher title rule detects |
| Zope | service | a:zope:zope | 36 | 0 | version-only | v:zope (sample) |
| HashiCorp Consul | service | a:hashicorp:consul | 35 | 0 | version-only | v:consul (container) |
| Net-SNMP SNMP Agent | service | a:net-snmp:net-snmp | 35 | 0 | not-version | sysDescr describes the host kernel, not net-snmp |
| Payload CMS | service | a:payloadcms:payload | 35 | 0 | no-known-location |  |
| Hono | service | a:hono:hono | 34 | 0 | no-known-location |  |
| SOPlanning | service | a:soplanning:soplanning | 34 | 0 | no-known-location |  |
| Cisco APIC | service | a:cisco:application_policy_infrastructure_controller | 33 | 0 | no-known-location |  |
| Macromedia JRun | service | a:macromedia:jrun | 33 | 0 | no-known-location |  |
| Microsoft Skype for Business | service | a:microsoft:skype_for_business | 33 | 0 | no-known-location |  |
| Weblate | service | a:weblate:weblate | 33 | 0 | version-only | v:weblate (source) |
| Dotclear | service | a:dotclear:dotclear | 32 | 0 | no-known-location |  |
| OpenCms | service | a:alkacon:opencms | 32 | 0 | version-only | v:opencms-generator (sample) |
| Tenable Security Center | service | a:tenable:security_center | 32 | 0 | no-known-location |  |
| Octopus Deploy | service | a:octopus:octopus_deploy | 31 | 0 | no-known-location |  |
| REDAXO | service | a:redaxo:redaxo | 31 | 0 | no-known-location |  |
| Bitweaver | service | a:bitweaver:bitweaver | 30 | 0 | no-known-location |  |
| Textpattern CMS | service | a:textpattern:textpattern | 30 | 0 | no-known-location |  |
| Apache JSPWiki | service | a:apache:jspwiki | 29 | 0 | version-only | v:jspwiki (source) |
| CubeCart | service | a:cubecart:cubecart | 29 | 0 | version-only | v:cubecart-footer (sample) |
| Statamic | service | a:statamic:statamic | 29 | 0 | no-known-location |  |
| Twik | service | a:twiki:twiki | 29 | 0 | no-known-location |  |
| TWiki | service | a:twiki:twiki | 29 | 0 | no-known-location |  |
| WP Fastest Cache | service | a:wpfastestcache:wp_fastest_cache | 29 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| SAP Internet Graphics Server | service | a:sap:internet_graphics_server | 28 | 0 | no-known-location |  |
| XenForo | service | a:xenforo:xenforo | 28 | 0 | no-known-location |  |
| Imagely NextGEN Gallery | service | a:imagely:nextgen_gallery | 27 | 0 | same CPE captured |  |
| Misskey | service | a:misskey:misskey | 27 | 0 | no-known-location |  |
| YaBB | service | a:yabb:yabb | 27 | 0 | no-known-location |  |
| Zen Cart | service | a:zen-cart:zen_cart | 27 | 0 | no-known-location |  |
| a-blog cms | service | a:appleple:a-blog_cms | 26 | 0 | version-only | v:a-blog (sample) |
| Brizy WordPress | service | a:brizy:brizy | 26 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| EC-CUBE | service | a:lockon:ec-cube | 26 | 0 | no-known-location |  |
| GetSimple CMS | service | a:get-simple:getsimple_cms | 26 | 0 | no-known-location |  |
| Portainer | service | a:portainer:portainer | 26 | 0 | no-known-location |  |
| Ampache | service | a:ampache:ampache | 25 | 0 | no-known-location |  |
| Dokuwiki | service | a:dokuwiki:dokuwiki | 25 | 0 | version-only | v:dokuwiki (sample) |
| Essential Blocks | service | a:wpdeveloper:essential_blocks | 25 | 0 | not-version | wplab 5.4.0, 6.5.3: front-end assets carry a content hash |
| Fork CMS | service | a:fork-cms:fork_cms | 25 | 0 | no-known-location |  |
| NetApp ONTAP | service | a:netapp:ontap | 25 | 0 | no-known-location |  |
| Subrion | service | a:intelliants:subrion | 25 | 0 | other-url | admin panel only |
| Symantec Messaging Gateway | service | a:symantec:messaging_gateway | 25 | 0 | no-known-location |  |
| Harbor | service | a:linuxfoundation:harbor | 24 | 0 | other-url | /api/v2.0/systeminfo |
| OpenStack Horizon | service | a:openstack:horizon | 24 | 0 | no-known-location |  |
| SimpleSAMLphp | service | a:simplesamlphp:simplesamlphp | 24 | 0 | no-known-location |  |
| Nagios Log Server | service | a:nagios:log_server | 23 | 0 | no-known-location |  |
| Observium | service | a:observium:observium | 23 | 0 | no-known-location |  |
| Cisco Adaptive Security Appliance | hw | h:cisco:adaptive_security_appliance | 22 | 0 | hardware |  |
| Graylog | service | a:graylog:graylog | 22 | 0 | no-known-location |  |
| Matomo Analytics | service | a:matomo:matomo | 22 | 0 | other-url | CHANGELOG.md |
| nopCommerce | service | a:nopcommerce:nopcommerce | 22 | 0 | no-known-location |  |
| Tableau Server | service | a:tableau:tableau_server | 22 | 0 | not-version | data-buildId |
| Webmin Usermin | service | a:webmin:usermin | 22 | 0 | no-known-location |  |
| Bagisto | service | a:webkul:bagisto | 21 | 0 | no-known-location |  |
| Bold Page Builder | service | a:bold-themes:bold_page_builder | 21 | 0 | version-only | v:wp-bold-page-builder (wordpress) |
| BookStack | service | a:bookstackapp:bookstack | 21 | 0 | version-only | v:bookstack (source) |
| ImpressCMS | service | a:impresscms:impresscms | 21 | 0 | no-known-location |  |
| InstantCMS | service | a:instantcms:instantcms | 21 | 0 | no-known-location |  |
| Ktor | service | a:jetbrains:ktor | 21 | 0 | no-known-location |  |
| MeterSphere | service | a:metersphere:metersphere | 21 | 0 | no-known-location |  |
| OpenVPN Access Server | service | a:openvpn:openvpn_access_server | 21 | 0 | no-known-location |  |
| Oracle ILOM | os | o:oracle:integrated_lights_out_manager_firmware | 21 | 0 | not-version | Server header carries the web server version |
| PHP-Nuke | service | a:phpnuke:php-nuke | 21 | 0 | no-known-location |  |
| Windows Admin Center | service | a:microsoft:windows_admin_center | 21 | 0 | no-known-location |  |
| eZ Publish | service | a:ez:ez_publish | 20 | 0 | no-known-location |  |
| NodeBB | service | a:nodebb:nodebb | 20 | 0 | no-known-location |  |
| Poll Maker | service | a:ays-pro:poll_maker | 20 | 0 | no-known-location |  |
| Rapid7 (NeXpose) | service | a:rapid7:nexpose | 20 | 0 | not-version | see Rapid7 Nexpose |
| Rapid7 Nexpose | service | a:rapid7:nexpose | 20 | 0 | not-version | Server: NSC/0.6.4 is a component version |
| Rapid7 Nexpose/InsightVM | service | a:rapid7:nexpose | 20 | 0 | not-version | Server: NSC/0.6.4 is a component version |
| Spring Boot | service | a:vmware:spring_boot | 20 | 0 | hidden |  |
| Vaultwarden | service | a:dani-garcia:vaultwarden | 20 | 0 | other-url | container vaultwarden 1.37.5: the web vault page at / carries no version; only /api/version and /api/config do |
| Xerox WorkCentre | hw | h:xerox:workcentre | 20 | 0 | hardware |  |
| Invision Power Board | service | a:invisioncommunity:invision_power_board | 19 | 0 | version-only | v:ipb (sample), v:ipb-ips (sample) |
| phpwcms | service | a:phpwcms:phpwcms | 19 | 0 | other-url | files under the installation, not the site pages |
| Sylius | service | a:sylius:sylius | 19 | 0 | no-known-location |  |
| Vanilla | service | a:vanillaforums:vanilla | 19 | 0 | no-known-location |  |
| CS Cart | service | a:cs-cart:cs-cart | 18 | 0 | no-known-location |  |
| IBM Lotus Sametime | service | a:ibm:lotus_sametime | 18 | 0 | no-known-location |  |
| ikiwiki | service | a:ikiwiki:ikiwiki | 18 | 0 | no-known-location |  |
| Lansweeper | service | a:lansweeper:lansweeper | 18 | 0 | version-only | v:lansweeper (sample) |
| Nuxt.js | service | a:nuxt:nuxt | 18 | 0 | no-known-location |  |
| Bitrix24 | service | a:bitrix24:bitrix24 | 17 | 0 | no-known-location |  |
| Craft Commerce | service | a:craftcms:craft_commerce | 17 | 0 | no-known-location |  |
| Jupyter Notebook | service | a:jupyter:notebook | 17 | 0 | no-known-location |  |
| Rapid7 Metasploit | service | a:rapid7:metasploit | 17 | 0 | no-known-location |  |
| Dokeos | service | a:dokeos:dokeos | 16 | 0 | version-only | v:dokeos-footer (sample) |
| Etherpad | service | a:etherpad:etherpad | 16 | 0 | no-known-location |  |
| etherpad | service | a:etherpad:etherpad | 16 | 0 | no-known-location |  |
| Home-Assistant | service | a:home-assistant:home-assistant | 16 | 0 | no-known-location |  |
| HP iLO 4 | os | o:hp:integrated_lights-out_4_firmware | 16 | 0 | no-known-location |  |
| Jetpack | service | a:automattic:jetpack | 16 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| Microsoft Lync Server | service | a:microsoft:lync_server | 16 | 0 | no-known-location |  |
| OpenKM | service | a:openkm:openkm | 16 | 0 | no-known-location |  |
| TinyMCE | service | a:tiny:tinymce | 16 | 0 | version-only | v:cdn-tinymce (library) |
| Vvveb CMS | service | a:vvveb:vvveb | 16 | 0 | no-known-location |  |
| WebsiteBaker | service | a:websitebaker:websitebaker | 16 | 0 | no-known-location |  |
| Wolf CMS | service | a:wolfcms:wolf_cms | 16 | 0 | version-only | v:wolfcms-footer (sample) |
| YesWiki | service | a:yeswiki:yeswiki | 16 | 0 | no-known-location |  |
| jsPDF | service | a:parall:jspdf | 15 | 0 | version-only | v:cdn-jspdf (library) |
| Jupyter Server | service | a:jupyter:jupyter_server | 15 | 0 | no-known-location |  |
| LiteSpeed Cache | service | a:litespeedtech:litespeed_cache | 15 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| Litespeed Cache | service | a:litespeedtech:litespeed_cache | 15 | 0 | hidden | see LiteSpeed Cache |
| Mono | service | a:mono:mono | 15 | 0 | no-known-location |  |
| PeerTube | service | a:framasoft:peertube | 15 | 0 | no-known-location |  |
| Cisco Wireless LAN Controller | hw | h:cisco:wireless_lan_controller | 14 | 0 | hardware |  |
| Microsoft SQL Server Reporting Services | service | a:microsoft:sql_server_reporting_services | 14 | 0 | no-known-location |  |
| NexusPHP | service | a:nexusphp:nexusphp | 14 | 0 | no-known-location |  |
| VirtueMart | service | a:virtuemart:virtuemart | 14 | 0 | no-known-location |  |
| Apache Guacamole | service | a:apache:guacamole | 13 | 0 | no-known-location |  |
| DeskPro | service | a:deskpro:deskpro | 13 | 0 | no-known-location |  |
| Icinga Web | service | a:icinga:icinga_web_2 | 13 | 0 | no-known-location |  |
| OpenX | service | a:openx:openx | 13 | 0 | version-only | v:openx-generator (sample) |
| OXID eShop | service | a:oxid-esales:eshop | 13 | 0 | coarse | generator gives the major (Version 6) |
| Pagekit | service | a:pagekit:pagekit | 13 | 0 | no-known-location |  |
| Sympa | service | a:sympa:sympa | 13 | 0 | no-known-location |  |
| Web2py | service | a:web2py:web2py | 13 | 0 | no-known-location |  |
| WikkaWiki | service | a:wikkawiki:wikkawiki | 13 | 0 | no-known-location |  |
| Apache Druid | service | a:apache:druid | 12 | 0 | no-known-location |  |
| Cisco IMC | service | a:cisco:integrated_management_controller | 12 | 0 | no-known-location |  |
| Cisco IMC | os | a:cisco:integrated_management_controller | 12 | 0 | no-known-location |  |
| Cisco IMC | hw | a:cisco:integrated_management_controller | 12 | 0 | no-known-location |  |
| Croogo | service | a:croogo:croogo | 12 | 0 | no-known-location |  |
| Flarum | service | a:flarum:flarum | 12 | 0 | no-known-location |  |
| HP iLO 3 | os | o:hp:integrated_lights-out_3_firmware | 12 | 0 | no-known-location |  |
| Progress OpenEdge Explorer | service | a:progress:openedge | 12 | 0 | no-known-location |  |
| SEOPress | service | a:seopress:seopress | 12 | 0 | no-known-location |  |
| Spree | service | a:spreecommerce:spree | 12 | 0 | no-known-location |  |
| total.js | service | a:totaljs:total.js | 12 | 0 | no-known-location |  |
| Ubercart | service | a:ubercart:ubercart | 12 | 0 | no-known-location |  |
| YUI | service | a:yahoo:yui | 12 | 0 | version-only | v:cdn-yui (library) |
| AbanteCart | service | a:abantecart:abantecart | 11 | 0 | no-known-location |  |
| Akaunting | service | a:akaunting:akaunting | 11 | 0 | no-known-location |  |
| Amazon OpenSearch | service | a:amazon:opensearch | 11 | 0 | no-known-location |  |
| CakePHP | service | a:cakephp:cakephp | 11 | 0 | version-only | v:cakephp (source) |
| Contao | service | a:contao:contao_cms | 11 | 0 | other-url | the back-end login page and CHANGELOG.md |
| Delinea Secret Server | service | a:delinea:secret_server | 11 | 0 | no-known-location |  |
| Elgg | service | a:elgg:elgg | 11 | 0 | no-known-location |  |
| Marked | service | a:marked_project:marked | 11 | 0 | version-only | v:cdn-marked (library) |
| MITRE CALDERA | service | a:mitre:caldera | 11 | 0 | no-known-location |  |
| Power BI Report Server | service | a:microsoft:power_bi_report_server | 11 | 0 | other-url | /reports/api/v2.0/System |
| TightVNC Desktop | service | a:tightvnc:tightvnc | 11 | 0 | no-known-location |  |
| Cisco MDS 9000 | hw | h:cisco:mds_9000 | 10 | 0 | hardware |  |
| Citrix Netscaler | service | a:citrix:netscaler | 10 | 0 | same CPE captured |  |
| Flyspray | service | a:flyspray:flyspray | 10 | 0 | no-known-location |  |
| Lodash | service | a:lodash:lodash | 10 | 0 | version-only | v:cdn-lodash (library), v:file-lodash (library) |
| Otter Blocks | service | a:themeisle:otter_blocks | 10 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| Rundeck | service | a:pagerduty:rundeck | 10 | 0 | version-only | v:rundeck (sample) |
| SvelteKit | service | a:svelte:sveltekit | 10 | 0 | no-known-location |  |
| Transmission | service | a:transmissionbt:transmission | 10 | 0 | no-known-location |  |
| Bitwarden Server | service | a:bitwarden:server | 9 | 0 | hidden |  |
| Ektron CMS | service | a:ektron:ektron_content_management_system | 9 | 0 | no-known-location |  |
| ELOG | service | a:elog_project:elog | 9 | 0 | no-known-location |  |
| Magnolia CMS | service | a:magnolia-cms:magnolia_cms | 9 | 0 | no-known-location |  |
| Mautic | service | a:mautic:mautic | 9 | 0 | no-known-location |  |
| Munin | service | a:munin-monitoring:munin | 9 | 0 | no-known-location |  |
| NextAuth.js | service | a:nextauth.js:next-auth | 9 | 0 | no-known-location |  |
| OpnForm | service | a:jhumanj:opnform | 9 | 0 | no-known-location |  |
| ProjectPier | service | a:projectpier:projectpier | 9 | 0 | no-known-location |  |
| Pterodactyl Panel | service | a:pterodactyl:panel | 9 | 0 | no-known-location |  |
| Pulse CMS | service | a:pulsecms:pulse_cms | 9 | 0 | no-known-location |  |
| Sawmill | service | a:sawmill:sawmill | 9 | 0 | version-only | v:sawmill (sample) |
| The Events Calendar | service | a:stellarwp:the_events_calendar | 9 | 0 | version-only | v:wp-events-calendar (wordpress) |
| Winter CMS | service | a:wintercms:winter | 9 | 0 | no-known-location |  |
| Asgaros Forum | service | a:asgaros:asgaros_forum | 8 | 0 | no-known-location |  |
| FluxBB | service | a:fluxbb:fluxbb | 8 | 0 | version-only | v:fluxbb-footer (sample) |
| Foswiki | service | a:foswiki:foswiki | 8 | 0 | no-known-location |  |
| Hasura | service | a:hasura:graphql_engine | 8 | 0 | no-known-location |  |
| Indexhibit | service | a:indexhibit:indexhibit | 8 | 0 | no-known-location |  |
| LG webOS | os | o:lg:webos | 8 | 0 | no-known-location |  |
| MaxSite CMS | service | a:max-3000:maxsite_cms | 8 | 0 | no-known-location |  |
| Mojolicious | service | a:mojolicious:mojolicious | 8 | 0 | no-known-location |  |
| Peel | service | a:peel:peel_shopping | 8 | 0 | no-known-location |  |
| Proxmox Virtual Environment | service | a:proxmox:virtual_environment | 8 | 0 | version-only | v:proxmox-ve (source) |
| Rapid7 InsightVM | service | a:rapid7:insightvm | 8 | 0 | no-known-location |  |
| SerenityOS | os | o:serenityos:serenityos | 8 | 0 | no-known-location |  |
| Bricks | service | a:bricksbuilder:bricks | 7 | 0 | no-known-location |  |
| Cisco Nexus 1000V | hw | h:cisco:nexus_1000v | 7 | 0 | hardware |  |
| Complianz | service | a:really-simple-plugins:complianz | 7 | 0 | hidden | only in a JavaScript variable (needs a browser) |
| HCL Commerce | service | a:hcltechsw:hcl_commerce | 7 | 0 | no-known-location |  |
| JupyterHub | service | a:jupyter:jupyterhub | 7 | 0 | version-only | v:jupyterhub (container) |
| Mayan-EDMS Mayan EDMS | service | a:mayan-edms:mayan_edms | 7 | 0 | no-known-location |  |
| MyCred | service | a:wpexperts:mycred | 7 | 0 | no-known-location |  |
| Nagios Network Analyzer | service | a:nagios:network_analyzer | 7 | 0 | no-known-location |  |
| Northstar Club Management | service | a:globalnorthstar:northstar_club_management | 7 | 0 | no-known-location |  |
| Open Web Analytics | service | a:openwebanalytics:open_web_analytics | 7 | 0 | no-known-location |  |
| phpPgAdmin | service | a:phppgadmin_project:phppgadmin | 7 | 0 | no-known-location |  |
| Ubiquiti UniFi Video | service | a:ui:unifi_video | 7 | 0 | no-known-location |  |
| VMware View | service | a:vmware:view | 7 | 0 | no-known-location |  |
| webEdition | service | a:webedition:webedition_cms | 7 | 0 | no-known-location |  |
| xtCommerce | service | a:xt-commerce:xt-commerce | 7 | 0 | hidden | only in a JavaScript variable (needs a browser) |
| Blocksy Companion | service | a:creativethemes:blocksy_companion | 6 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| BoidCMS | service | a:boidcms:boidcms | 6 | 0 | no-known-location |  |
| Cosmoshop | service | a:cosmoshop:cosmoshop | 6 | 0 | no-known-location |  |
| Cotonti | service | a:cotonti:cotonti_siena | 6 | 0 | no-known-location |  |
| Docker | service | a:docker:engine | 6 | 0 | no-known-location |  |
| HP iLO 2 | os | o:hp:integrated_lights-out_2_firmware | 6 | 0 | no-known-location |  |
| IBM Tivoli Storage FlashCopy Manager | service | a:ibm:tivoli_storage_flashcopy_manager | 6 | 0 | no-known-location |  |
| Kodi Media Server | service | a:kodi:kodi | 6 | 0 | no-known-location |  |
| Lynx Technology Twonky Media Server | service | a:lynxtechnology:twonky_server | 6 | 0 | no-known-location |  |
| Mermaid | service | a:mermaid_project:mermaid | 6 | 0 | version-only | v:cdn-mermaid (library) |
| OpenWrt LuCI | service | a:openwrt:luci | 6 | 0 | version-only | v:luci-footer (sample) |
| Payara Server | service | a:payara:payara | 6 | 0 | no-known-location |  |
| PostHog | service | a:posthog:posthog | 6 | 0 | no-known-location |  |
| Premio Chaty | service | a:premio:chaty | 6 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| ProcessWire | service | a:processwire:processwire | 6 | 0 | no-known-location |  |
| PyroCMS | service | a:pyrocms:pyrocms | 6 | 0 | no-known-location |  |
| RabbitMQ | service | a:vmware:rabbitmq | 6 | 0 | hidden | container rabbitmq 4.2.9-management, 4.3.7-management: the management UI page carries no version (only /api/overview, authenticated) |
| Squiz Matrix | service | a:squiz:matrix | 6 | 0 | no-known-location |  |
| status.net | service | a:status:statusnet | 6 | 0 | version-only | v:statusnet-footer (sample) |
| Terminalfour | service | a:terminalfour:terminalfour | 6 | 0 | no-known-location |  |
| Themify Builder | service | a:themify:builder | 6 | 0 | no-known-location |  |
| Tickera | service | a:tickera:tickera | 6 | 0 | no-known-location |  |
| Uptime Kuma | service | a:uptime.kuma:uptime_kuma | 6 | 0 | no-known-location |  |
| Visual Composer | service | a:visualcomposer:visual_composer_website_builder | 6 | 0 | no-known-location |  |
| VMware Horizon | service | a:vmware:horizon | 6 | 0 | other-url | /portal/info.jsp |
| Zimbra Collaboration Server | service | a:zimbra:collaboration_server | 6 | 0 | no-known-location |  |
| Appwrite | service | a:appwrite:appwrite | 5 | 0 | no-known-location |  |
| Batflat | service | a:batflat:batflat | 5 | 0 | no-known-location |  |
| Chevereto | service | a:chevereto:chevereto | 5 | 0 | version-only | v:chevereto (sample) |
| FreshTomato | os | o:freshtomato:freshtomato | 5 | 0 | hidden |  |
| Gambio | service | a:gambio:gambio | 5 | 0 | no-known-location |  |
| GFI Kerio Control | service | a:gfi:kerio_control | 5 | 0 | no-known-location |  |
| Google Web Toolkit | service | a:google:web_toolkit | 5 | 0 | no-known-location |  |
| HikaShop | service | a:hikashop:hikashop | 5 | 0 | no-known-location |  |
| Inductive Automation Ignition Gateway | service | a:inductiveautomation:ignition_gateway | 5 | 0 | hidden | the title names the gateway, not the release |
| Koa | service | a:koajs:koa | 5 | 0 | no-known-location |  |
| LiteSpeed | service | a:litespeedtech:litespeed_web_server | 5 | 0 | same CPE captured |  |
| Microsoft Outlook Web Access | service | a:microsoft:outlook_web_access | 5 | 0 | same CPE captured |  |
| openHAB | service | a:openhab:openhab | 5 | 0 | no-known-location |  |
| PixelYourSite | service | a:pixelyoursite:pixelyoursite | 5 | 0 | version-only | v:wp-pixelyoursite (wordpress) |
| Plesk | service | a:plesk:plesk | 5 | 0 | version-only | v:plesk-onyx (sample) |
| SEOmatic | service | a:nystudio107:seomatic | 5 | 0 | no-known-location |  |
| Streamlit | service | a:snowflake:streamlit | 5 | 0 | no-known-location |  |
| Swiper | service | a:swiperjs:swiper | 5 | 0 | version-only | v:cdn-swiper (library) |
| Tendenci | service | a:tendenci:tendenci | 5 | 0 | no-known-location |  |
| TomatoCart | service | a:tomatocart:tomatocart | 5 | 0 | no-known-location |  |
| Zimbra | service | a:zimbra:zimbra | 5 | 0 | other-url | /js/zimbraMail/share/model/ZmSettings.js |
| AlternC | service | a:alternc:alternc | 4 | 0 | no-known-location |  |
| Ametys | service | a:ametys:ametys | 4 | 0 | other-url | admin login only |
| Blesta | service | a:phillipsdata:blesta | 4 | 0 | no-known-location |  |
| DESTOON | service | a:destoon:destoon_b2b | 4 | 0 | no-known-location |  |
| Erxes | service | a:erxes:erxes | 4 | 0 | no-known-location |  |
| Faveo | service | a:ladybirdweb:faveo_helpdesk | 4 | 0 | no-known-location |  |
| FileRun | service | a:filerun:filerun | 4 | 0 | no-known-location |  |
| GoDaddy CoBlocks | service | a:godaddy:coblocks | 4 | 0 | version-only | v:wp-coblocks (wordpress) |
| Google Gerrit | service | a:google:gerrit | 4 | 0 | same CPE captured |  |
| Grin | service | a:grin:grin | 4 | 0 | no-known-location |  |
| Lenovo XClarity Controller | service | a:lenovo:xclarity_controller | 4 | 0 | no-known-location |  |
| LEPTON | service | a:lepton-cms:lepton | 4 | 0 | no-known-location |  |
| Microsoft Azure App Service on Azure Stack | service | a:microsoft:azure_app_service_on_azure_stack | 4 | 0 | no-known-location |  |
| Moment.js | service | a:momentjs:moment | 4 | 0 | version-only | v:cdn-moment (library), v:file-moment (library) |
| Nelio Testing | service | a:neliosoftware:nelio_ab_testing | 4 | 0 | no-known-location |  |
| Netdata | service | a:netdata:netdata | 4 | 0 | same CPE captured |  |
| OpenMediaVault | service | a:openmediavault:openmediavault | 4 | 0 | no-known-location |  |
| OutSystems | service | a:outsystems:outsystems | 4 | 0 | no-known-location |  |
| Perfmatters | service | a:perfmatters:perfmatters | 4 | 0 | no-known-location |  |
| Phoenix | service | a:phoenixframework:phoenix | 4 | 0 | no-known-location |  |
| Pygments | service | a:pygments:pygments | 4 | 0 | no-known-location |  |
| RafflePress | service | a:seedprod:rafflepress | 4 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| Rhymix | service | a:rhymix:rhymix | 4 | 0 | no-known-location |  |
| Riverbed RiOS | os | o:riverbed:rios | 4 | 0 | not-version | X-RBT-Optimized-By names the appliance on the path, not the scanned host |
| Sakai | service | a:sakailms:sakai | 4 | 0 | no-known-location |  |
| Smart Slider 3 | service | a:nextendweb:smart_slider_3 | 4 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| SVG Support | service | a:benbodhi:svg_support | 4 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| XpressEngine | service | a:xpressengine:xpressengine | 4 | 0 | no-known-location |  |
| 3CX Web Server | service | a:3cx:3cx_web_server | 3 | 0 | no-known-location |  |
| AdGuard Home | service | a:adguard:adguardhome | 3 | 0 | no-known-location |  |
| Alpine Linux | os | o:alpinelinux:alpine_linux | 3 | 0 | platform |  |
| Argo CD | service | a:linuxfoundation:argo-cd | 3 | 0 | other-url | /api/version |
| Broadcom SiteMinder | service | a:broadcom:siteminder | 3 | 0 | no-known-location |  |
| Burst | service | a:burst-statistics:burst_statistics | 3 | 0 | no-known-location |  |
| Cisco NAM | hw | h:cisco:network_analysis_module | 3 | 0 | hardware |  |
| Colorlib Activello | service | a:colorlib:activello | 3 | 0 | no-known-location |  |
| Creativ.eMail | service | a:constantcontact:creative_mail | 3 | 0 | no-known-location |  |
| DataLife Engine | service | a:dleviet:datalife_engine | 3 | 0 | no-known-location |  |
| Disqus | service | a:disqus:disqus_comment_system | 3 | 0 | no-known-location |  |
| Django CMS | service | a:django-cms:django_cms | 3 | 0 | no-known-location |  |
| Easy Accordion | service | a:techearty:easy_accordion | 3 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| Email Encoder for Wordpress | service | a:onlineoptimisation:email_encoder | 3 | 0 | no-known-location |  |
| EWWW Image Optimizer | service | a:ewww:image_optimizer | 3 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| Forgejo | service | a:forgejo:forgejo | 3 | 0 | version-only | v:forgejo (container), v:forgejo-footer (container) |
| Genesis blocks | service | a:wpengine:genesis_blocks | 3 | 0 | not-version | wplab 3.1.3, 3.1.11: front-end assets carry a timestamp |
| InfluxData InfluxDB | service | a:influxdata:influxdb | 3 | 0 | fixed only |  |
| Jitsi | service | a:jitsi:jitsi | 3 | 0 | no-known-location |  |
| jPlayer | service | a:happyworm:jplayer | 3 | 0 | no-known-location |  |
| Kubernetes minikube | service | a:kubernetes:minikube | 3 | 0 | no-known-location |  |
| lwIP | service | a:lwip_project:lwip | 3 | 0 | no-known-location |  |
| MachoThemes NewsMag | service | a:machothemes:newsmag | 3 | 0 | no-known-location |  |
| ManageEngine Desktop Central | service | a:manageengine:desktop_central | 3 | 0 | no-known-location |  |
| Mandriva Linux | os | o:mandriva:linux | 3 | 0 | fixed only |  |
| math.js | service | a:mathjs:mathjs | 3 | 0 | version-only | v:cdn-mathjs (library) |
| Netgear Prosafe Firmware | os | o:netgear:prosafe_firmware | 3 | 0 | no-known-location |  |
| Node-RED | service | a:nodered:node-red | 3 | 0 | no-known-location |  |
| PayPal | service | a:paypal:paypal | 3 | 0 | no-known-location |  |
| Plain Black WebGUI | service | a:plainblack:webgui | 3 | 0 | same CPE captured |  |
| Post Affiliate Pro | service | a:qualityunit:post_affiliate_pro | 3 | 0 | no-known-location |  |
| Raneto | service | a:raneto_project:raneto | 3 | 0 | no-known-location |  |
| SABnzbd | service | a:sabnzbd:sabnzbd | 3 | 0 | no-known-location |  |
| Smartstore biz | service | a:smartstore:smartstore | 3 | 0 | version-only | v:smartstore (sample) |
| sNews | service | a:snewscms:snews | 3 | 0 | version-only | v:snews (sample) |
| SpeedyCache | service | a:softaculous:speedycache | 3 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| Twilight CMS | service | a:twilightcms:twilight_cms | 3 | 0 | no-known-location |  |
| WebAssembly | service | a:webassembly:webassembly | 3 | 0 | no-known-location |  |
| WooCommerce Stripe Payment Gateway | service | a:woocommerce:stripe_payment_gateway | 3 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| WSO2 Carbon | service | a:wso2:carbon | 3 | 0 | no-known-location |  |
| ACME micro_httpd | service | a:acme:micro_httpd | 2 | 0 | no-known-location |  |
| Amiro.CMS | service | a:amiro:amiro.cms | 2 | 0 | no-known-location |  |
| AquilaCMS | service | a:aquila-cms:aquilacms | 2 | 0 | no-known-location |  |
| Arc | service | a:arc:arc | 2 | 0 | no-known-location |  |
| Bigware | service | a:bigware:bigware_shop | 2 | 0 | no-known-location |  |
| Bootstrap Table | service | a:bootstrap-table:bootstrap_table | 2 | 0 | version-only | v:cdn-bootstrap-table (library) |
| Cesanta Mongoose OS | os | o:cesanta:mongoose_os | 2 | 0 | no-known-location |  |
| Colorlib Illdy | service | a:colorlib:illdy | 2 | 0 | no-known-location |  |
| Colorlib Shapely | service | a:colorlib:shapely | 2 | 0 | no-known-location |  |
| Daphne | service | a:djangoproject:daphne | 2 | 0 | no-known-location |  |
| DataTables | service | a:datatables:datatables.net | 2 | 0 | version-only | v:cdn-datatables (library) |
| Drupal Commerce | service | a:commerceguys:commerce | 2 | 0 | no-known-location |  |
| ElasticPress | service | a:10up:elasticpress | 2 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| Eleanor CMS | service | a:eleanor-cms:eleanor_cms | 2 | 0 | no-known-location |  |
| Eltex NTP-2 Firmware | os | o:eltex-co:ntp-2_firmware | 2 | 0 | no-known-location |  |
| Eltex NTP-RG-1402G Firmware | os | o:eltex-co:ntp-rg-1402g_firmware | 2 | 0 | no-known-location |  |
| Encode uvicorn | service | a:encode:uvicorn | 2 | 0 | no-known-location |  |
| eSyndiCat | service | a:intelliants:esyndicat | 2 | 0 | version-only | v:esyndicat-generator (sample), v:esyndicat-footer (sample) |
| ExtendThemes Materialis | service | a:extendthemes:materialis | 2 | 0 | no-known-location |  |
| ExtJS | service | a:sencha:ext_js | 2 | 0 | hidden | only in a JavaScript variable (needs a browser) |
| F5 BigIP | service | a:f5:big-ip | 2 | 0 | hidden | see F5 BIG-IP |
| Fastly | service | a:fastly:fastly | 2 | 0 | no-known-location |  |
| Flutter | service | a:flutter:flutter | 2 | 0 | no-known-location |  |
| GDPR Cookie Consent Plugin by Webtoffee | service | a:webtoffee:gdpr_cookie_consent | 2 | 0 | no-known-location |  |
| GuppY | service | a:freeguppy:guppy | 2 | 0 | version-only | v:guppy (sample) |
| HP iLO 4 | hw | h:hp:integrated_lights-out_4 | 2 | 0 | hardware |  |
| Invision Community | service | a:invisioncommunity:invisioncommunity | 2 | 0 | no-known-location |  |
| iThemes Security | service | a:ithemes:security | 2 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| JetEngine | service | a:crocoblock:jetengine | 2 | 0 | no-known-location |  |
| Jetpack Boost | service | a:automattic:jetpack_boost | 2 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| Jive | service | a:jivesoftware:jive | 2 | 0 | no-known-location |  |
| JobberBase | service | a:jobberbase:jobberbase | 2 | 0 | no-known-location |  |
| JSZip | service | a:jszip_project:jszip | 2 | 0 | version-only | v:cdn-jszip (library) |
| KACE K1000 | hw | h:dell:kace_k1000_systems_management_appliance | 2 | 0 | hardware |  |
| Kubernetes NGINX Ingress Controller | service | a:kubernetes:nginx_ingress_controller | 2 | 0 | no-known-location |  |
| MailChimp | service | a:thinkshout:mailchimp | 2 | 0 | no-known-location |  |
| MotoCMS | service | a:motocms:motocms | 2 | 0 | no-known-location |  |
| Optimizely Content Management | service | a:episerver:episerver | 2 | 0 | no-known-location |  |
| Oxygen | service | a:soflyy:oxygen | 2 | 0 | no-known-location |  |
| Phoenix Cart | service | a:phoenixcart:ce_phoenix_cart | 2 | 0 | no-known-location |  |
| Play | service | a:playframework:play_framework | 2 | 0 | version-only | v:play1 (sample) |
| Reveal.js | service | a:revealjs:reveal.js | 2 | 0 | version-only | v:cdn-revealjs (library) |
| ShellInABox | service | a:shellinabox_project:shellinabox | 2 | 0 | no-known-location |  |
| Socket.io | service | a:socket:socket.io | 2 | 0 | not-version | a CDN client script says nothing about the server release |
| Sonarr | service | a:sonarr:sonarr | 2 | 0 | no-known-location |  |
| Supervisor | service | a:supervisord:supervisor | 2 | 0 | no-known-location |  |
| Ubiquiti EdgeOS | os | o:ui:edgeos | 2 | 0 | no-known-location |  |
| UNIX | os | o:unix:unix | 2 | 0 | platform | a generic OS name |
| Uvicorn | service | a:encode:uvicorn | 2 | 0 | no-known-location |  |
| WP-Optimize | service | a:updraftplus:wp-optimize | 2 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| Xajax | service | a:xajax:xajax | 2 | 0 | no-known-location |  |
| Xerox DocuShare | service | a:xerox:docushare | 2 | 0 | no-known-location |  |
| YunoHost | os | o:yunohost:yunohost | 2 | 0 | no-known-location |  |
| Akamai GHost | service | a:akamai:akamaighost | 1 | 0 | no-known-location |  |
| Amazon CloudFront Load Balancer | service | a:amazon:amazon_cloudfront | 1 | 0 | no-known-location |  |
| Aurelia | service | a:bluespire:aurelia_framework | 1 | 0 | no-known-location |  |
| Azuriom | service | a:azuriom:azuriom | 1 | 0 | no-known-location |  |
| Backbone.js | service | a:backbone_project:backbone | 1 | 0 | version-only | v:cdn-backbone (library), v:file-backbone (library) |
| Barracuda WAF | service | a:barracuda:web_application_firewall | 1 | 0 | no-known-location |  |
| Blinger | service | a:blinger:blinger | 1 | 0 | no-known-location |  |
| Citrix Hypervisor | service | o:citrix:hypervisor | 1 | 0 | version-only | v:citrix-hypervisor (sample) |
| Citrix NetScaler Gateway | hw | h:citrix:netscaler_gateway | 1 | 0 | hardware |  |
| Citrix Netscaler Gateway | hw | h:citrix:netscaler_gateway | 1 | 0 | hardware |  |
| Cloudflare | service | a:cloudflare:cloudflare | 1 | 0 | other-url | WordPress plugin readme.txt |
| CometD | service | a:cometd:cometd | 1 | 0 | no-known-location |  |
| Composite Products | service | a:woocommerce:composite_products | 1 | 0 | no-known-location |  |
| Covenant | service | a:cobbr:covenant | 1 | 0 | no-known-location |  |
| Custom Fonts | service | a:brainstormforce:custom_fonts | 1 | 0 | hidden | wplab (two releases): no asset of the plugin on a page that does not use it |
| CyberChimps Responsive | service | a:cyberchimps:responsive | 1 | 0 | no-known-location |  |
| D3 | service | a:d3.js_project:d3.js | 1 | 0 | version-only | v:cdn-d3 (library) |
| Dell OpenManage | service | a:dell:openmanage | 1 | 0 | no-known-location |  |
| eDirectory | service | a:arcasolutions:edirectory | 1 | 0 | version-only | v:edirectory (sample) |
| Elcom | service | a:elcom:elcom_cms | 1 | 0 | no-known-location |  |
| EMC Celerra | hw | h:emc:celerra_network_attached_storage | 1 | 0 | hardware |  |
| ExpressionEngine | service | a:ellislab:expressionengine | 1 | 0 | no-known-location | the one candidate (nuclei expressionengine-detect) is a generic "ExpressionEngine <n>" body match; the default templates print no version |
| ExtendThemes Calliope | service | a:extendthemes:calliope | 1 | 0 | no-known-location |  |
| ExtendThemes EmpowerWP | service | a:extendthemes:empowerwp | 1 | 0 | no-known-location |  |
| ExtendThemes Mesmerize | service | a:extendthemes:mesmerize | 1 | 0 | no-known-location |  |
| FastHTTP | service | a:fasthttp_project:fasthttp | 1 | 0 | no-known-location |  |
| Fat-Free Framework | service | a:fatfreeframework:fat-free_framework | 1 | 0 | no-known-location |  |
| Flurry Analytics | service | a:flurry:flurry-analytics-android | 1 | 0 | no-known-location |  |
| Formstone | service | a:formstone:formstone | 1 | 0 | no-known-location |  |
| GrandNode | service | a:grandnode:grandnode | 1 | 0 | no-known-location |  |
| GraphQL | service | a:graphql:graphql | 1 | 0 | no-known-location |  |
| Greyd.Suite | service | a:greyd:greyd.suite | 1 | 0 | no-known-location |  |
| Gutenberg | service | a:wordpress:gutenberg | 1 | 0 | version-only | v:wp-gutenberg (wordpress) |
| h5ai | service | a:h5ai_project:h5ai | 1 | 0 | no-known-location |  |
| HashThemes Total | service | a:hashthemes:total | 1 | 0 | no-known-location |  |
| HipServ | os | o:axentra:hipserv | 1 | 0 | not-version | the SSH banner carries the OpenSSH version |
| Hostinger | service | a:hostinger:hostinger | 1 | 0 | no-known-location |  |
| Hotaru CMS | service | a:hotarucms:hotarucms | 1 | 0 | version-only | v:hotaru (sample) |
| HP OpenView | service | a:hp:openview | 1 | 0 | not-version | Server headers carry component versions (BBC, coda, ovbbccb) |
| iXsystems FreeNAS Firmware | os | o:ixsystems:freenas_firmware | 1 | 0 | no-known-location |  |
| JivoChat | service | a:jivochat:jivochat | 1 | 0 | hidden | third-party chat widget; version only in a JavaScript variable |
| Johnson Controls Metasys | service | a:johnsoncontrols:metasys | 1 | 0 | no-known-location |  |
| Jupyter BinderHub | service | a:jupyter:binderhub | 1 | 0 | no-known-location |  |
| Koala Framework | service | a:koala-framework:koala_framework | 1 | 0 | no-known-location |  |
| Lightbox | service | a:lightbox_photo_gallery_project:lightbox_photo_gallery | 1 | 0 | no-known-location |  |
| Macromedia Breeze | service | a:macromedia:breeze | 1 | 0 | no-known-location |  |
| mdBook | service | a:rust-lang:mdbook | 1 | 0 | no-known-location |  |
| MetaSlider | service | a:matchalabs:metaslider | 1 | 0 | no-known-location |  |
| Meteor | service | a:meteor:meteor | 1 | 0 | hidden | only in a JavaScript variable (needs a browser) |
| Modified eCommerce | service | a:modified-shop:modified_ecommerce_shopsoftware | 1 | 0 | no-known-location |  |
| Mollom | service | a:acquia:mollom | 1 | 0 | no-known-location |  |
| MooTools | service | a:mootools:mootools | 1 | 0 | version-only | v:cdn-mootools (library) |
| NcFTPd Server | service | a:ncftp:ncftpd_server | 1 | 0 | no-known-location |  |
| noVNC | service | a:novnc:novnc | 1 | 0 | no-known-location |  |
| OpenBSD httpd | service | a:openbsd:openbsd | 1 | 0 | hidden |  |
| OpenUI5 | service | a:sap:openui5 | 1 | 0 | version-only | v:cdn-openui5 (library) |
| Orchard Core | service | a:orchardcore:orchard_core | 1 | 0 | no-known-location |  |
| OWASP Zed Attack Proxy | service | a:owasp:zed_attack_proxy | 1 | 0 | no-known-location |  |
| Papermerge | service | a:papermerge:papermerge | 1 | 0 | no-known-location |  |
| Phabricator | service | a:phacility:phabricator | 1 | 0 | no-known-location |  |
| Phacility Phabricator | service | a:phacility:phabricator | 1 | 0 | no-known-location |  |
| Phlox | service | a:averta:phlox | 1 | 0 | no-known-location |  |
| prettyPhoto | service | a:no-margin-for-errors:prettyphoto | 1 | 0 | version-only | v:cdn-prettyphoto (library) |
| Prometheus Alertmanager | service | a:prometheus:alertmanager | 1 | 0 | no-known-location |  |
| PyScript | service | a:pyscript:pyscript | 1 | 0 | no-known-location |  |
| ReDoc | service | a:redocly:redoc | 1 | 0 | hidden | only in a JavaScript variable |
| Revel | service | a:revel:revel | 1 | 0 | no-known-location |  |
| Riot.js | service | a:riot.js:riot-compiler | 1 | 0 | not-version | the CPE names riot-compiler, not the library a page loads |
| RStudio Connect | service | a:rstudio:connect | 1 | 0 | no-known-location |  |
| SAP | service | a:sap:netweaver_application_server | 1 | 0 | same CPE captured |  |
| script.aculo.us | service | a:script.aculo.us:script.aculo.us | 1 | 0 | version-only | v:cdn-scriptaculous (library) |
| Select2 | service | a:select2:select2 | 1 | 0 | version-only | v:cdn-select2 (library), v:file-select2 (library) |
| Sharetribe | service | a:sharetribe:sharetribe | 1 | 0 | no-known-location |  |
| Shiny | service | a:rstudio:shiny_server | 1 | 0 | no-known-location |  |
| Sophos Email Appliance | service | a:sophos:email_appliance | 1 | 0 | no-known-location |  |
| Spiceworks Help Desk Server | service | a:spiceworks:help_desk_server | 1 | 0 | no-known-location |  |
| SQL Buddy | service | a:sqlbuddy:sql_buddy | 1 | 0 | no-known-location |  |
| Starlet | service | a:kazuho:starlet | 1 | 0 | no-known-location |  |
| Strikingly | service | a:strikingly:strikingly | 1 | 0 | no-known-location |  |
| Stripe | service | a:stripe:stripe | 1 | 0 | hidden | third-party payment script; version only in a JavaScript variable |
| Synology Web Station | service | a:synology:web_station | 1 | 0 | no-known-location |  |
| Theme Horse NewsCard | service | a:themehorse:newscard | 1 | 0 | no-known-location |  |
| ThemeGrill ColorMag | service | a:themegrill:colormag | 1 | 0 | same CPE captured |  |
| Totara | service | a:totara:totara | 1 | 0 | no-known-location |  |
| Ultimate Tables | service | a:webpsilon:ultimate_tables | 1 | 0 | no-known-location |  |
| UMI.CMS | service | a:umi-cms:umi.cms | 1 | 0 | no-known-location |  |
| Ushahidi | service | a:ushahidi:ushahidi | 1 | 0 | no-known-location |  |
| WatchGuard Fireware XTM | service | a:watchguard:fireware_xtm | 1 | 0 | no-known-location |  |
| Weblication | service | a:weblication:cms_core_&_grid | 1 | 0 | no-known-location |  |
| Wink | service | a:wink:wink | 1 | 0 | hidden | only in a JavaScript variable |
| WooCommerce Subscriptions | service | a:woocommerce:subscriptions | 1 | 0 | no-known-location |  |
| XMB | service | a:xmbforum2:xmb | 1 | 0 | no-known-location |  |
| Zyxel ZyNOS firmware | os | o:zyxel:zynos_firmware | 1 | 0 | no-known-location |  |
| Afterpay | service | a:afterpay:afterpay | 0 | 0 | hidden | third-party payment widget; version only in a JavaScript variable |
| Amazon S3 | service | a:amazon:amazon_simple_storage_service | 0 | 0 | no-known-location |  |
| Bolt CMS | service | a:bolt:bolt | 0 | 0 | no-known-location |  |
| Brocade Fabric OS | os | o:brocade:fabric_operating_system | 0 | 0 | no-known-location |  |
| Calibre-Web | service | a:calibre-web_project:calibre-web | 0 | 0 | no-known-location |  |
| Citrix NetScaler SDX Gateway | hw | h:citrix:netscaler_sdx | 0 | 0 | hardware |  |
| CloudFlare Load Balancer | service | a:cloudflare:load_balancing | 0 | 0 | no-known-location |  |
| D-Link DCS-825L | hw | h:dlink:dcs-825l | 0 | 0 | hardware |  |
| Eltex NTP-2 | hw | h:eltex-co:ntp-2 | 0 | 0 | hardware |  |
| Eltex NTP-RG-1402G | hw | h:eltex-co:ntp-rg-1402g | 0 | 0 | hardware |  |
| experiencedCMS | service | a:experiencedcms:experiencedcms | 0 | 0 | no-known-location |  |
| Express | service | a:expressjs:express | 0 | 0 | no-known-location |  |
| FatPipe Networks IPVPN | hw | h:fatpipeinc:ipvpn | 0 | 0 | hardware |  |
| FatPipe Networks MPVPN | hw | h:fatpipeinc:mpvpn | 0 | 0 | hardware |  |
| FatPipe Networks WARP | hw | h:fatpipeinc:warp | 0 | 0 | hardware |  |
| Google Chromecast | hw | h:google:chromecast | 0 | 0 | hardware |  |
| Google Web Server | service | a:google:web_server | 0 | 0 | hidden | Server: gws carries no version (the recog candidate names the product only) |
| Google Web Services | service | a:google:web_server | 0 | 0 | hidden | see Google Web Server |
| HP iLO | hw | h:hp:integrated_lights-out | 0 | 0 | same CPE captured |  |
| HP iLO 3 | hw | h:hp:integrated_lights-out_3 | 0 | 0 | hardware |  |
| Melis Platform | service | a:melisplatform:melisplatform | 0 | 0 | no-known-location |  |
| Mersive SolsticePod | hw | h:mersive:solstice_pod | 0 | 0 | hardware |  |
| Miniflux | service | a:miniflux:miniflux | 0 | 0 | no-known-location |  |
| Mongrel | service | a:zed_shaw:mongrel | 0 | 0 | same CPE captured |  |
| Philips Hue | hw | h:philips:hue | 0 | 0 | hardware |  |
| Ruckus Zone Director | hw | h:ruckus:zonedirector | 0 | 0 | hardware |  |
| SMA Sunny WebBox | hw | h:sma:sunny_webbox | 0 | 0 | hardware |  |
| Software House iSTAR Ultra | hw | h:swhouse:istar_ultra | 0 | 0 | hardware |  |
| Symantec Mail Security for SMTP | service | a:symantec:mail_security_for_smtp | 0 | 0 | no-known-location |  |
| Ubiquiti EdgeSwitch | hw | h:ui:edgeswitch | 0 | 0 | hardware |  |
| Ubiquiti UniFi | service | a:ui:unifi | 0 | 0 | not-version | the version recog reads from the SNMP sysDescr is the device firmware, not the UniFi Network application |
| uPortal | service | a:apereo:uportal | 0 | 0 | version-only | v:uportal (sample), v:uportal-header (sample) |
| VMware vCenter Converter | service | a:vmware:vcenter_converter | 0 | 0 | no-known-location |  |
| Xerox WorkCentre Pro | hw | h:xerox:workcentre_pro | 0 | 0 | hardware |  |
| Zyxel USG20-VPN | hw | h:zyxel:usg20-vpn | 0 | 0 | hardware |  |
| Zyxel USG40 | hw | h:zyxel:usg40 | 0 | 0 | hardware |  |
| Zyxel USG60 | hw | h:zyxel:usg60 | 0 | 0 | hardware |  |
