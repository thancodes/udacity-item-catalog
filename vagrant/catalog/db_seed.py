import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Course

engine = create_engine('sqlite:///item-catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

current_user = User(name='System Administrator', email='system@administrator.com')
session.add(current_user)
session.commit()

fixtures = json.loads(open('fixtures.json', 'rb').read())

for t in fixtures['categories']:
    category = Category(name=t['name'],
                        description=t['description'],
                        url=t['url'])
    session.add(category)
    session.commit()

for c in fixtures['courses']:
    course = Course(name=c['name'],
                    description=c['description'],
                    number=c['number'],
                    url=c['url'],
                    thumbnail_url=c['thumbnail_url'],
                    category_id=c['category_id'],
                    user=current_user)
    session.add(course)
    session.commit()
