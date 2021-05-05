# Flask-Auction-Final
This is the final project for my 2021 Python-Flask class at BPCC

The goal of this project was to create a dynamic silent auction website where user could register/login and view items and make bids on them.
Some of the requierments of this prject were to have three different user roles, users, auctioneers and an admin. the users can view items and make bids on them. The auctioneers can create new items and end an auction.
The admin can create new users, change a user's or auctioneer's password as well as change a user's role.
Throught the whole project all sesitive information is hashed and the admin credentials are stored with environment variables.

The project also includes a file called fake.py. This is a script that when run will create a SQLite database and fill it with fake test information, such as fake users and items.  
