from db_functions import *

#insert into user (name, child) values ('Ben',True);

def add_user(name):
    db_add_user(name)

def modify_user(id:int):
    db_modify_user(id)

#THIS NEEDS TO BE REWRITTEN, DATABASE TABLES AND ALL.
#SEE OTHER CODE IN active_dns_query_thread.py IT NEEDS TO BE REWRITTEN TO MATCH.
#RIGHT NOW WE CAN'T ADD NEW SOURCES (BE THEY DOMAINS OR PORTS)
#FIX_ME fix_me
def add_source(name, domains):
    db_insert("source",['domain',],[name,])

        disneyPlusDomains={"parentDomain":'DisneyPlus',
                "subdomains":['disneyplus.com','bam.nr-data.net','cdn.registerdisney.go.com','cws.conviva.com', 'd9.flashtalking.com','disney-portal.my.onetrust.com','disneyplus.bn5x.net','js-agent.newrelic.com']}
        netflixDomains={"parentDomain":'Netflix',
                "subdomains":['netflix.com','netflix.net','nflxext.com','nflximg.com','nflxvideo.net']}
        youtubeDomains={"parentDomain":'Youtube',
                "subdomains":['youtube.com','googlevideo.com','youtu.be','youtube-ui.l.google.com','ytimg.l.google.com','ytstatic.l.google.com','youtubei.googleapis.com']}
