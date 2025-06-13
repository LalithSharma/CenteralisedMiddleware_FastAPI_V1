from sqlalchemy.orm import Session
from auth.utils import get_password_hash
from users.models import Role, Channel,User, UserChannel, UserRole, Channel, Role, StatusEnum
from .database import engine

def seed_roles(session: Session):
    roles = [
        {"name": "admin", "status": StatusEnum.active},
        {"name": "partner", "status": StatusEnum.active},
        {"name": "guest", "status": StatusEnum.active},
    ]
    
    for role in roles:
        # Check if the role already exists by name
        existing_role = session.query(Role).filter_by(name=role["name"]).first()
        if not existing_role:
            session.add(Role(**role))
    
    session.commit()
    print("Roles seeded successfully.")

# Seed Channels
def seed_channels(session: Session):
    channels = [
        {
            "name": "mtm",
            "base_url": "https://v2.mpp.paris/api/v2",
            "auth_url": "",
            "api_key": "pCgLAJqR8ThXwuM762sX7wtNFMQhPQ1TohJRkHqRno",
            "status": StatusEnum.active,
        },
        {
            "name": "mpp",
            "base_url": "",
            "auth_url": "",
            "api_key": "",
            "status": StatusEnum.active,
        },
        {
            "name": "gdp",
            "base_url": "https://v2.mpp.paris/api/v2",
            "auth_url": "",
            "api_key": "M1GLrfhIoADCWJbCqzFqjZCtkaf7Au9Gcqbjru16",
            "status": StatusEnum.active,
        },
    ]
    
    for channel in channels:
        # Check if the channel already exists by name
        existing_channel = session.query(Channel).filter_by(name=channel["name"]).first()
        if not existing_channel:
            session.add(Channel(**channel))
    
    session.commit()
    print("Channels seeded successfully.")
    

def seed_users(session: Session):
    users = [
        {
            "email": "admin@mail.com",
            "hashed_password": get_password_hash("admin123"),
            "status": StatusEnum.active,
            "roles": ["admin"],
            "channels": ["mtm"],
        },
        {
            "email": "user@mail.com",
            "hashed_password": get_password_hash("user123"),
            "status": StatusEnum.active,
            "roles": ["partner"],
            "channels": ["mpp"],
        },
    ]

    for user_data in users:
        # Check if the user already exists by email
        existing_user = session.query(User).filter_by(email=user_data["email"]).first()
        if not existing_user:
            # Create and add user
            new_user = User(
                email=user_data["email"],
                hashed_password=user_data["hashed_password"],
                status=user_data["status"],
            )
            session.add(new_user)
            session.flush()  # Ensure user ID is available

            # Assign roles
            for role_name in user_data["roles"]:
                role = session.query(Role).filter_by(name=role_name).first()
                if role:
                    session.add(UserRole(user_id=new_user.id, role_id=role.id))

            # Assign channels
            for channel_name in user_data["channels"]:
                channel = session.query(Channel).filter_by(name=channel_name).first()
                if channel:
                    session.add(UserChannel(user_id=new_user.id, channel_id=channel.id))

    session.commit()
    print("Users seeded successfully.")
