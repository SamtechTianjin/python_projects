import sqlite3

"""
sqlite3 database operation
"""

DB = "Test.db"

def open_close_database(func):
    def wrapper():
        try:
            connection = sqlite3.connect(DB)
            cursor = connection.cursor()
            cursor.execute("""""")
        except Exception as e:
            print("[connection] \033[1;31m{0}\033[0m".format(e))
        else:
            print("Opened database successfully.")
            try:
                func(connection)
            except Exception as e:
                print("[function] \033[1;31m{0}\033[0m".format(e))
            finally:
                connection.close()
    return wrapper

def create_table(DB,create_cmd):
    connection = sqlite3.connect(DB)
    print("Opened database successfully.")
    cursor = connection.cursor()
    cursor.execute(create_cmd)
    print("Table created successfully.")
    connection.commit()
    connection.close()

def insert_data(insert_cmd):
    connection = sqlite3.connect(DB)
    print("Opened database successfully.")
    cursor = connection.cursor()
    print(parse_insert(insert_cmd))
    cursor.execute(parse_insert(insert_cmd))
    print("Records created successfully.")
    connection.commit()
    connection.close()

def parse_insert(insert_cmd):
    return "insert into " + "account (DATE,AMOUNT,ITEM,FLAG,USER) values ('{0}',{1},'{2}','{3}','{4}');".format(insert_cmd[0],insert_cmd[1],insert_cmd[2],insert_cmd[3],insert_cmd[4])

def select_data(select_cmd):
    connection = sqlite3.connect(DB)
    print("Opened database successfully.")
    cursor = connection.cursor()
    cursor.execute(select_cmd)
    rows = cursor.fetchall()
    connection.commit()
    connection.close()
    return rows

def update_data(update_cmd):
    connection = sqlite3.connect(DB)
    print("Opened database successfully.")
    cursor = connection.cursor()
    cursor.execute(update_cmd)
    print("Updated done.")
    connection.commit()
    connection.close()

def delete_data(delete_cmd):
    connection = sqlite3.connect(DB)
    print("Opened database successfully.")
    cursor = connection.cursor()
    cursor.execute(delete_cmd)
    print("Deleted done.")
    connection.commit()
    connection.close()

if __name__ == '__main__':
    print("Sqlite3 for python3...")
    create_cmd = "create table" + " account " + """(
    ID integer primary key autoincrement not null,
    DATE date not null ,
    AMOUNT float not null default 0,
    ITEM char(32) not null,
    FLAG char(32) not null,
    USER char(32) not null default 'admin');"""
    try:
        create_table(DB,create_cmd)
    except Exception as e:
        print("Exception: {0}".format(e))
    """ Insert data """
    insert_cmd = ("2018-09-01",99.9,"Football","支出","Jack")
    try:
        insert_data(insert_cmd)
    except Exception as e:
        print("Exception: {0}".format(e))
    """ Select data """
    select_cmd = "select * from" + " account;"
    rows = select_data(select_cmd)
    for row in rows:
        print(row)
    """ Update data """
    update_cmd = "update account" + " set ITEM='午餐',FLAG='支出',USER='小明' where ID=1"
    try:
        update_data(update_cmd)
    except Exception as e:
        print("Exception: {0}".format(e))
    """ Delete data """
    delete_cmd = "delete from" + " account where ID>13"
    try:
        delete_data(delete_cmd)
    except Exception as e:
        print("Exception: {0}".format(e))
    """ Select data """
    select_cmd = "select * from" + " account;"
    rows = select_data(select_cmd)
    for row in rows:
        print(row)
    """ 批量处理 """
    sql = "insert into" + " account(DATE,AMOUNT,ITEM,FLAG,USER) values(?,?,?,?,?);"
    param = [
        ("2018-10-09",19.9,"计程车","支出","刘明"),
        ("2018-10-09",49,"看电影","支出","刘明"),
        ("2018-10-10",7,"早餐","支出","刘明"),
        ("2018-10-10",39,"支付宝","收入","刘书阁"),
    ]
    connection = sqlite3.connect(DB)
    cursor = connection.cursor()
    cursor.executemany(sql,param)
    print("Inserted done.")
    connection.commit()
    connection.close()

























