from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)
    status = Column(String, default="Active")    
    services = Column(String, nullable=True)
    created_date = Column(DateTime, server_default=func.now(), nullable=False)
    update_date = Column(DateTime, onupdate=func.now())

    # Use class name "UserAPI", not table name "users_api"
    api_details = relationship("UserAPI", back_populates="user", uselist=True)

    def __repr__(self):
        return f"<users(id={self.id}, email={self.email}, username={self.username}, role={self.role}, status={self.status})>"

class UserAPI(Base):
    __tablename__ = 'user_api'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    unique_token = Column(String, unique=True, nullable=True)
    token_expiration = Column(DateTime, nullable=True)
    login_time = Column(DateTime, server_default=func.now(), nullable=False) 
    token_type = Column(String, nullable=True) 
    created_date = Column(DateTime, server_default=func.now(), nullable=False)
    update_date = Column(DateTime, onupdate=func.now())

    # Use class name "User" here, not table name
    user = relationship("User", back_populates="api_details")

    def __repr__(self):
        return f"<user_api(id={self.id}, user_id={self.user_id}, token_expiration={self.token_expiration})>"
