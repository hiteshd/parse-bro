#!/usr/bin/python

import glob
import psycopg2
import sys,os
import urlparse
import psycopg2.extras

""" Connect to Database """
conn_string = ""

try:
    conn = psycopg2.connect(conn_string)

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    print "Connected to Database!\n"
except:
    print "Error\n New Users: Refer to the README"
    sys.exit(1)

# Bro Processed logs here
BRO_PROCESSED_PATH=""
# All Pcap files here
ALL_PCAP=""

def check_id(publisher_id,category_name):
    status={'ret':0,'id':0}
    query="select id from publishers where pub_id='%s' and category_name='%s'" % (publisher_id,category_name)
    cur.execute(query)
    conn.commit()
    status['ret']=cur.fetchone()
    if status['ret']:
        status['id']=1
    else:
        status['id']=0
    return status

def add_to_db(ident,publisher_id,category_name):
    status=check_id(publisher_id,category_name)
    query=""
    pub_id_pk=0
    if status['id']:
        pub_id_pk=status['ret'][0]
    else:
	query="insert into publishers(pub_id,category_name) values('%s','%s') returning id" % (publisher_id,category_name)
	cur.execute(query)
	conn.commit()
	pub_id_pk=cur.fetchone()[0]
       
    query="insert into publishers_md5(pub_id,exec_id) values('%s','%s')" % (pub_id_pk,ident)
    cur.execute(query)
    conn.commit()

def get_all_md5s():
    query="select id,md5 from executions"
    cur.execute(query)
    md5_list=[]
    tmp=cur.fetchall()
    for every in tmp:
	md5_list.append(every)
    return md5_list

def broify(md5,pcap):
    PROCESS_WITH_BRO="./broify.sh %s %s" % (pcap,md5)
    os.system(PROCESS_WITH_BRO)
    return 1

# Change this according to what you want to parse from the bro logs.
def parse_log(log_file,ident):

    fp=open(log_file)
    alllines=fp.readlines()
    i=0
    for line in alllines:
	i=i+1
	if i<=4:
	   continue
	fields=line.split('\t')
	if "category_name" in line:
	    urlparams=urlparse.parse_qs(fields[9])
	    add_to_db(ident,urlparams['publisher'][0],urlparams['category_name'][0])
	    print "Publisher id: %s\t||Category name: %s" % (urlparams['publisher'][0],urlparams['category_name'][0])

def get_path(execution):
    log_dir=BRO_PROCESSED_PATH+execution['md5']+"/"
    print execution['md5']
    if os.path.isdir(log_dir):
	for child_dir in [ name for name in os.listdir(log_dir) if os.path.isdir(os.path.join(log_dir, name)) ]: 
	    parse_log(log_dir+child_dir+"/http.log",execution['id'])
    for pcap in glob.glob(ALL_PCAP+"%s/%s/*%s*" % (execution['md5'][0],execution['md5'][1],execution['md5'])):
	if broify(execution['md5'],pcap):
	    parse_log("%s/http.log" % execution['md5'],execution['id'])
	
	
def main():
    
    all_md5s=get_all_md5s()

    for one_md5 in all_md5s:
	get_path(one_md5)	
	print "="*50

if __name__=="__main__":
    main()	
