from sqlalchemy.orm import Session
from auth.utils import get_password_hash
from users.models import APIRoute, Role, Channel,User, UserChannel, UserRole, Channel, Role, StatusEnum
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
            "channels": ["mtm"],
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

            for role_name in user_data["roles"]:
                role = session.query(Role).filter_by(name=role_name).first()
                if role:
                    session.add(UserRole(user_id=new_user.id, role_id=role.id))

            for channel_name in user_data["channels"]:
                channel = session.query(Channel).filter_by(name=channel_name).first()
                if channel:
                    session.add(UserChannel(user_id=new_user.id, channel_id=channel.id))

    session.commit()
    print("Users seeded successfully.")


def seed_api_routes(session: Session):
        
    routes = [
            {"method": "GET", "path": "/clients", "status": StatusEnum.active, "cache_key_prefix": "Client_list_cache", "maxcache":3600, "description": "Fetch all clients"},
            {"method": "GET", "path": "/clients/{client_id}", "status": StatusEnum.active, "cache_key_prefix": "Client_data_cache", "maxcache":3600, "description": "Fetch client details"},
            {"method": "GET", "path": "/clients/{client_id}/products", "status": StatusEnum.active, "cache_key_prefix": "Client_products_cache", "maxcache":3600, "description": "Fetch all products for a client"},
            {"method": "GET", "path": "/clients/{client_id}/products/{product_id}", "status": StatusEnum.active, "cache_key_prefix": "Product_data_cache", "maxcache":3600, "description": "Fetch specific product details"},
            {"method": "GET", "path": "/clients/{client_id}/products/{product_id}/calendar", "status": StatusEnum.active, "cache_key_prefix": "Product_calendar_cache", "maxcache":3600, "description": "Fetch product calendar"},
            {"method": "GET", "path": "/clients/{client_id}/receptionists", "status": StatusEnum.active, "cache_key_prefix": "Receptionists_cache", "maxcache":3600, "description": "Fetch all receptionists for a client"},
            {"method": "GET", "path": "/clients/{client_id}/receptionists/{receptionist_id}", "status": StatusEnum.active, "cache_key_prefix": "Receptionist_data_cache", "maxcache":3600, "description": "Fetch specific receptionist details"},
            {"method": "GET", "path": "/clients/{client_id}/commissions", "status": StatusEnum.active, "cache_key_prefix": "Commissions_cache", "maxcache":3600, "description": "Fetch all commissions for a client"},
            {"method": "GET", "path": "/clients/{client_id}/commissions/{commission_id}", "status": StatusEnum.active, "cache_key_prefix": "Commission_data_cache", "maxcache":3600, "description": "Fetch specific commission details"},
            {"method": "GET", "path": "/clients/{client_id}/orders", "status": StatusEnum.active, "cache_key_prefix": "Orders_cache", "maxcache":3600, "description": "Fetch all orders for a client"},
            {"method": "GET", "path": "/clients/{client_id}/orders/{order_id}", "status": StatusEnum.active, "cache_key_prefix": "Order_data_cache", "maxcache":3600, "description": "Fetch specific order details"},
            {"method": "GET", "path": "/clients/{client_id}/orders/invoice/{invoice_id}", "status": StatusEnum.active, "cache_key_prefix": "Invoice_data_cache", "maxcache":3600, "description": "Fetch invoice details for an order"},
            {"method": "GET", "path": "/clients/{client_id}/orders/attachment/{attachment_id}", "status": StatusEnum.active, "cache_key_prefix": "Attachment_data_cache", "maxcache":3600, "description": "Fetch attachment details for an order"},
            {"method": "GET", "path": "/clients/{client_id}/orders/voucher/{voucher_id}", "status": StatusEnum.active, "cache_key_prefix": "Voucher_data_cache", "maxcache":3600, "description": "Fetch voucher details for an order"},
            {"method": "GET", "path": "/clients/{client_id}/orders/prepaidvoucher/{prepaidvoucher_id}", "status": StatusEnum.active, "cache_key_prefix": "PrepaidVoucher_data_cache", "maxcache":3600, "description": "Fetch prepaid voucher details for an order"},
        ]    
    try:
        for route in routes:
            # Check if this route already exists
            exists = session.query(APIRoute).filter_by(
                method=route["method"],
                path=route["path"]
            ).first()

            if not exists:
                new_route = APIRoute(
                    method=route["method"],
                    path=route["path"],
                    status=route["status"],
                    cache_key_prefix=route["cache_key_prefix"],
                    maxcache=route["maxcache"],
                    description=route["description"]
                )
                session.add(new_route)

        session.commit()
        print("API Routes seeded successfully (skipped duplicates).")

    except Exception as e:
        session.rollback()
        print(f"Error seeding API Routes: {e}")

    finally:
        session.close()