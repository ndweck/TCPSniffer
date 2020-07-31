"""
this script creates the db schema from scratch
"""
from sqlalchemy import create_engine, Column, Integer, String, Float, MetaData, Table

engine = create_engine('sqlite:///test.db', echo=True)
metadata = MetaData()
ip = Table('iptraffic', metadata, Column('ip', String, primary_key=True), Column('bytes', Integer),
           Column('tx_time', Float), Column('peak', Float), Column('last_update', Float))
port = Table('porttraffic', metadata, Column('port', Integer, primary_key=True), Column('bytes', Integer),
             Column('tx_time', Float), Column('peak', Float), Column('last_update', Float))
ip_history = Table('ipHistory', metadata, Column('id', Integer, primary_key=True), Column('bandwidth', Integer),
                   Column('ip', String), sqlite_autoincrement=True)
port_history = Table('portHistory', metadata, Column('id', Integer, primary_key=True), Column('bandwidth', Integer),
                     Column('port', Integer), sqlite_autoincrement=True)
metadata.create_all(engine)
