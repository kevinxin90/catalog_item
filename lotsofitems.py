from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Catalog, Base, Item, User

engine = create_engine('postgresql://catalog:catalog@localhost:5432/catalogwithusers')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com")
session.add(User1)
session.commit()

# Items for Soccer
catalog1 = Catalog(user_id=1, name="Soccer")

session.add(catalog1)
session.commit()

item1 = Item(user_id=1, title="Soccer Cleats",
             description="The shoes", catalog=catalog1)

session.add(item1)
session.commit()

item2 = Item(user_id=1, title="Jersey",
             description="The shirt", catalog=catalog1)

session.add(item2)
session.commit()


# Items for Basketball
catalog2 = Catalog(user_id=1, name="Basketball")
session.add(catalog2)
session.commit()

# Items for Baseball
catalog3 = Catalog(user_id=1, name="Baseball")
session.add(catalog3)
session.commit()

item1 = Item(user_id=1, title="Bat",
             description="The bat", catalog=catalog3)
session.add(item1)
session.commit()

# Items for Frisbee
catalog4 = Catalog(user_id=1, name="Frisbee")
session.add(catalog4)
session.commit()

# Items for Snowboarding
catalog5 = Catalog(user_id=1, name="Snowboarding")
session.add(catalog5)
session.commit()

item1 = Item(user_id=1, title="Snowboard",
             description="Best for any terrain and condition.",
             catalog=catalog5)

session.add(item1)
session.commit()


print("added catalog items!")
