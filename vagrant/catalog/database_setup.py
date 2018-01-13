import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Category(Base):
    __tablename__ = 'categories'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(500))
    url = Column(String(255))

    @property
    def serialize(self):
        # JSON serializer method
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'url': self.url,
        }


class Course(Base):
    __tablename__ = 'courses'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(2000))
    number = Column(String(20))
    url = Column(String(255))
    thumbnail_url = Column(String(255))
    category_id = Column(Integer, ForeignKey('categories.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship(User)

    @property
    def serialize(self):
        #  JSON serializer method
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'number': self.number,
            'url': self.url,
            'thumbnail_url': self.thumbnail_url,
            'category_id': self.category_id,
        }


if __name__ == '__main__':
    engine = create_engine("sqlite:///item-catalog.db")
    Base.metadata.create_all(engine)
