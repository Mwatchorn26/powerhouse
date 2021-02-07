#https://towardsdatascience.com/do-you-know-python-has-a-built-in-database-d553989c87bd

# This direct DB system is probably not safe and secure in a multitude of ways.
# I should probably use classes for Users, Devices, etc... 
# I should also use an ORM, perhaps something like PEEWEE
# http://charlesleifer.com/blog/peewee-a-lightweight-python-orm---original-post/

import sqlite3 as sl
import json
import pudb
import os
import psutil 
import logging

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

def create_db():

    con = sl.connect('screentime.db')
    #pudb.set_trace()

    with con:

        # Enable Foreign Keys
        con.execute("""
            PRAGMA foreign_keys = ON;
        """)

        # Table of Users
        con.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                child BOOLEAN,
                mac TEXT,
                encrypted_pwd TEXT
            );
        """)

        # Table of devices
        con.execute("""
            CREATE TABLE IF NOT EXISTS device (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                mac_addr TEXT NOT NULL,
                ip_addr TEXT NOT NULL,
                hostname TEXT,
                user_id INTEGER,
                FOREIGN KEY (user_id)
                REFERENCES user (id)
                );
	    """)

        # Table of Access Restrictions
        # example days_of_week: ['1','4']
        con.execute("""
            CREATE TABLE IF NOT EXISTS access (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                start_time TEXT,
                end_time TEXT,
                days_of_week TEXT,
                sources_list TEXT,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES user (id)
                );
            """)
        #con.execute("""DROP TABLE IF EXISTS dns_records;""")
        con.execute("""
            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                ip_address TEXT,
                date TEXT,
                ttl TEXT,
                source TEXT,
                parentDomain TEXT
                );
            """)
        print("about to create manuf_by_mac")
        #Online repository of manufacturers and their assigned MAC address ranges
        #https://gitlab.com/wireshark/wireshark/-/raw/master/manuf
        #con.execute("""DROP TABLE IF EXISTS manuf_by_mac;""")
        con.execute("""
            CREATE TABLE IF NOT EXISTS manuf_by_mac (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                mac TEXT,
                common_name TEXT,
                full_name TEXT
                );
            """)
        print("completed manuf_by_mac")
        #TO RELOAD THE MANUFACTURERS TABLE:
        #sqlite> create table tempImport (mac TEXT, common_name TEXT,full_name TEXT); 
        #sqlite> mode csv tempImport 
        #sqlite> .import ./file_cache/manuf2commas2.csv tempImport   
        #sqlite> INSERT INTO manuf_by_mac(mac, common_name,full_name) SELECT * FROM tempImport; 
        #sqlite>  DROP TABLE tempImport;
        #sqlite> select count(*) from manuf_by_mac ;
        #count(*)
        #41619



        #SOURCES are domains and their IPs that we may want to block.
        con.execute("""
            CREATE TABLE IF NOT EXISTS source (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                port TEXT,
                parent_id INTEGER NOT NULL,
                FOREIGN KEY (parent_id) REFERENCES source (id)
                );
            """)


        con.commit()
        #con.close()

def is_open(path):
    path='screentime.db'
    for proc in psutil.process_iter():
        try:
            files = proc.get_open_files()
            if files:
                for _file in files:
                    if _file.path == path:
                        return True    
        except psutil.NoSuchProcess as err:
            print(err)
        return False
    #USAGE:
    #con = sqlite3.connect('screentime.db')
    #path = os.path.abspath('screentime.db')
    #print(is_open(path))
    #con.close()
    #print(is_open(path))


def db_add_dns_record(name, ip_address,parentDomain):
    #print("domain name: " + name)
    #print("ip_address:  " + ip_address)

    resultset = db_select("dns_records",("ip_address",),(ip_address,))
    if len(resultset)==0:
        db_insert("dns_records",["name","ip_address","parentDomain"],[name,ip_address,parentDomain])
    
    #conn = sl.connect('screentime.db')
    #values = (name, ip_address)
    #c = conn.cursor()
    #c.execute("SELECT * FROM dns_records WHERE ip_address=(?)",(ip_address,))
    #recordset = c.fetchall()
    #if len(recordset)>0:
    #    pass #No need to update, except perhaps the TTL? Update
    #else:
    #    #Insert
    #    c.execute("INSERT INTO dns_records(name, ip_address) values (?,?)",(name, ip_address))
    #conn.commit()
    #c.close()
    

def db_get_manuf_by_mac(mac):
    print("Running 'db get manuf by mac'")
    mac = mac.upper()
    conn = sl.connect('screentime.db')
    #values = (name, ip_address)
    c = conn.cursor()
    c.execute("SELECT common_name FROM manuf_by_mac WHERE mac=(?);",(mac[:8],))
    recordset = c.fetchall()
    if len(recordset)==1:    #Exact Match
        return str(recordset[0][0])
    #elif len(recordset)>1:  #May Matches, refine search
    #    c.execute("SELECT common_name FROM manuf_by_mac WHERE mac LIKE '(?)%'",(mac,))
    #    recordset = c.fetchall()
    #    if len(recordset)>0
    #        return str(recordset[0])
    else:
        return ''

def db_select(table, column_list, value_list):
    """Return a recordset (array of arrays aka rows of data)"""
    conn = sl.connect('screentime.db')
    cur = conn.cursor()
    #conn.set_trace_callback(print)
    #print("column_list[0]: " + column_list[0])
    whereClause = " ".join([x+"=?" for x in column_list])
    if len(whereClause)>2:
        whereClause = " WHERE " + whereClause
    else:
        whereClause=''
    sqlString = "SELECT * FROM " + table + whereClause + ";"
    logging.debug(sqlString)
    cur.execute(sqlString,value_list)
    recordset = cur.fetchall()
    cur.close()
    return recordset

def db_selectLike(table, column, value):
    """Return a recordset (array of arrays aka rows of data)"""
    conn = sl.connect('screentime.db')
    cur = conn.cursor()
    #conn.set_trace_callback(print)
    #print("column_list[0]: " + column_list[0])
    whereClause = column + " LIKE '%" + value + "%'"
    sqlString = "SELECT * FROM " + table + ' WHERE ' + whereClause + ";"
    logging.debug(sqlString)
    conn.set_trace_callback(print)
    cur.execute(sqlString)
    recordset = cur.fetchall()
    cur.close()
    return recordset


def db_selectFromList(table, column, value_list):
    """Return a recordset (array of arrays aka rows of data)"""
    conn = sl.connect('screentime.db')
    cur = conn.cursor()
    #conn.set_trace_callback(print)
    whereClause = " WHERE " + column + " IN (" +  ",".join(["?" for x in value_list]) + ")"
    sqlString = "SELECT * FROM " + table + whereClause + ";"
    #print(sqlString)
    cur.execute(sqlString,value_list)
    recordset = cur.fetchall()
    cur.close()
    return recordset


def db_selectDistinct(table, column_list):
    """Return a recordset (array of arrays aka rows of data)"""
    conn = sl.connect('screentime.db')
    cur = conn.cursor()
    conn.set_trace_callback(print)
    columns = ",".join(["?" for x in column_list]) 
    logging.debug("columns: " + columns)
    #sqlString = "SELECT DISTINCT " + columns + " FROM ?;"
    sqlString = "SELECT DISTINCT " + str(column_list[0]) + " FROM " + table +";"
    logging.debug(sqlString)
    #values = column_list + [table,]
    #print(values)
    #cur.execute(sqlString,values)
    cur.execute(sqlString)
    recordset = cur.fetchall()
    cur.close()
    return recordset
    #print(f"ABCD " +  {table})


def db_update(table, update_columns, update_values, where_columns, where_values):
    """
    Update 1 or more fields in a table row.
    FIX ME
    #>>> db_update("device",["mac_addr",],["A",],["hostname",],["Album",])
    Example:      UPDATE device ip_addr=? WHERE mac_addr=(?);
    UPDATE device mac_addr=? WHERE hostname=(?);
    ['A', 'Album']
    Traceback (most recent call last):
          File "<stdin>", line 1, in <module>
            File "/home/pi/screentime/mw/db_functions.py", line 148, in db_update
                cur.execute(sqlString, sqlArgs)
    sqlite3.OperationalError: near "mac_addr": syntax error
    """
    
    conn = sl.connect('screentime.db')
    cur = conn.cursor()
    #conn.set_trace_callback(print)
    conn.set_trace_callback(logging.debug)
    logging.debug("Example:      UPDATE device SET ip_addr=? WHERE mac_addr=(?);")
    sqlString = ("UPDATE " + table + " SET " + \
            ", ".join([x+"=?" for x in update_columns]) + \
             " WHERE " + "AND,".join([x+"=(?)" for x in where_columns]) \
            +";")
    logging.debug(sqlString)
    #pudb.set_trace()
    sqlArgs = update_values + where_values
    logging.debug(sqlArgs)
    cur.execute(sqlString, sqlArgs)
    conn.commit()
    cur.close()



def db_add_device(ip,mac,hostname,devices):
    """
    Inserts or Updates the MAC record in the "device" table
    """
    logging.info("\n\n NEW DEVICE DETECTED (ip="+ip+" mac="+mac+" hostname: "+ hostname+")")
    logging.debug("IP: " + ip)
    logging.debug("MAC: " + mac)
    mac = mac.upper()

    existing_mac = [device[1] for device in devices if mac == device[1]]

    if len(existing_mac)>=1:    #MAC Address exists, IP is different, Update IP
        #UPDATE
        logging.debug("UPDATE command running for device")
        db_update("device",['ip_addr',],[ip,],['mac_addr',],[existing_mac[0],])
        logging.info("Updated Device ID ("+hostname+"): ")
    else:
        
        ##This next section just determines what we want to store for the hostname

        #logger.info("Original hostname: " + hostname)
        #logger.info("Manufacturer as hostname: " + new_hostname)
        #occurances_of_dot = hostname.count(".")
        #if occurances_of_dot==4:
        #    hostname=new_hostname

        logging.debug("INSERT command running for device")
        #If hostname is blank, get the device manufactured based off the MAC address
        if hostname.lower() in ['','unknown']:
            logging.warning("hostname is empty. get MFG")
            hostname = db_get_manuf_by_mac(mac)
        db_insert("device",['mac_addr','ip_addr','hostname'],[mac,ip,hostname])
        logging.info("New Device ID ("+hostname+") inserted ")


def db_insert(table,column_names_list, column_values_list):
    conn = sl.connect('screentime.db')
    cur = conn.cursor()
    #conn.set_trace_callback(print)
    #print("table: " +table)
    #print("column_names: (" + ",".join(column_names_list) +")" )
    #print(" VALUES ("+ 
    #print(",".join(["?" for x in column_names_list]))
    sqlString = ("INSERT INTO " + table + \
            "(" + ",".join(column_names_list) +") " + \
             " VALUES (" + ",".join(["?" for x in column_names_list]) \
            +");")
    #print(sqlString)
    #return
    #pudb.set_trace()
    cur.execute(sqlString, column_values_list)
    ##insert into user (name, child) values ('Ben',True);
    conn.commit()
    cur.close()


# >>> import datetime
# >>> datetime.datetime.today()
# datetime.datetime(2012, 3, 23, 23, 24, 55, 173504)
# >>> datetime.datetime.today().weekday()
# 4
# From the documentation:
# Return the day of the week as an integer, where Monday is 0 and Sunday is 6.

# import json
# numbers = ["1", "2", "3"]
# json_numbers = json.dumps(numbers)
# print(json_numbers)          # ["1", "2", "3"]

# sqlite> INSERT INTO artist VALUES(3, 'Sammy Davis Jr.');
# sqlite> UPDATE track SET trackartist = 3 WHERE trackname = 'Mr. Bojangles';
