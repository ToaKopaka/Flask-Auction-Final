from faker import Faker
from app import db, User, Bid, Item
from random import randint
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
import os

TestPassword = generate_password_hash("password")
# Commands to set up database is flask shell
# from app import db
# db.create_all()
# import fake
# fake.FakeAll()

# creates 1 admin 3 auctioneers with 5 items each and 10 users

def UserMaker(count=1):
    fake = Faker()
    i = 0
    
    while i < count:

        u = User(username=fake.first_name(),
                email=fake.email(),
                password_hash=TestPassword, #All users will have the password 'password' for testing I used sqlLiteStudio to see the name of a user and used that and the defualt password "password" to login
                is_auctioneer=False,
                is_admin=False)
        db.session.add(u)
        
        
        i += 1
        db.session.commit()

iterate through 5 items for each admin made
def AuctioneerMaker(count=1):
    fake = Faker()
    num = 5
    num2 = 0
    i = 0
    while i < count:
        num2 = 0
        a = User(username=fake.first_name(),
                email=fake.email(),
                password_hash=TestPassword,
                is_auctioneer=True,
                is_admin=False)
        db.session.add(a)
        db.session.commit()
        while num2 < num:
            I = Item(item_name=fake.company() + " Item",
                     is_over=False)
            db.session.add(I)
            db.session.commit()
            b = Bid(price = 0, user_id = a.id,  item_id = I.id)
            db.session.add(b)
            num2 += 1
            db.session.commit()
        i += 1
        db.session.commit()


def AdminMaker(count=1):
    # Hash the env variable password
    Apassword = generate_password_hash(os.environ['ADMINPASSWORD']) 
    a = User(username=os.environ['ADMINNAME'],
             email=os.environ['ADMINEMAIL'],
             password_hash=Apassword,
             is_auctioneer=True,
             is_admin=True)
    db.session.add(a)
    db.session.commit()

# single command to make all test data
def FakeAll():
    AdminMaker()
    AuctioneerMaker(3)
    UserMaker(10)
    
