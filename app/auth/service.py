import logging

from app.extensions import db
from app.auth.models import User, ROLES, DRIVER_STATUSES
from app.auth.utils import hash_password, verify_password, generate_password, normalize_phone
from app.auth.exceptions import(
    UserNotFoundError,
    DuplicateUserError,
    NotADriverError,
    InvalidDriverStatusError
)

#control panel for tracking and logging auth service operations
logger = logging.getLogger(__name__)

def onboard_driver(
    name:str,
    phone:str
) -> User:
   """
    Create a driver User with a generated temp password, and driver_status='pending documents'
    Calls communications.service.send_onboarding_sms()
   """

   normalized_phone = normalize_phone(phone)

   if User.query.filter_by(phone=normalized_phone).first() is not None:
       raise DuplicateUserError(f"User with phone {normalized_phone} already exists")
 

   temp_password = generate_password()

   driver = User(
       name=name.strip(),
       phone=normalized_phone,
       role="driver",
       password_hash=hash_password(temp_password),
       must_change_password=True,
       driver_status="pending_documents",
       is_active=True         
   )
   db.session.add(driver)
   db.session.commit()

   _send_onboarding_sms(normalized_phone, temp_password)

   return driver

def _send_onboarding_sms(phone:str, temp_password:str):
    """
     makes sure onboard_driver() doesn't fail if communications service doesn't exist or is down 
     the driver will still be created, but they won't receive the onboarding SMS
     manager can relay the temp password manually if needed
     will call communications.service.send_onboarding_sms(phone, temp_password) once it exists
    """

    try:
        from app.communications.service import send_onboarding_sms
        send_onboarding_sms(phone, temp_password)
    except ImportError:
        logger.warning(
            "Communications module not available yet- temp password for %s was Not sent via sms ",
            phone
        )
    except Exception:
        logger.exception(
            "sending onboarding sms failed for %s ", 
            phone
        )

def authenticate_user(
    identifier:str,
    password:str
) -> User | None:
    """
    Authenticate a user by their identifier (phone for drivers, email for managers) and password.
    Returns the User object if authentication is successful, otherwise returns None.
    """

    user = User.query.filter(
        (User.phone == identifier) | (User.email == identifier)
    ).first()

    if user is None or not user.is_active:
        return None

    if not verify_password(password, user.password_hash):
        return None

    return user

def get_user_by_id(user_id:int) -> User:
    """
    Retrieve a user by their ID.
    Raises UserNotFoundError if the user does not exist.
    """

    user = User.query.get(user_id)
    if user is None:
        raise UserNotFoundError(f"No User with id {user_id}")
    return user

def change_password(
    user_id:int,
    new_password:str
) -> None:
    """
    Sets must_change_password to False and updates the user's password hash.
    """

    user = get_user_by_id(user_id)
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    db.session.commit()

def _get_driver_or_raise(
    driver_id:int
) -> User:
    driver = get_user_by_id(driver_id)
    if driver.role != "driver":
        raise NotADriverError(f"User with id {driver_id} is a '{driver.role}' ")
    return driver

   
def get_driver_status(
    driver_id:int
) -> str:
    """Called by trips.service and trucks.service as a guard check. MUST exist — other
    modules depend on this exact function."""
    driver = _get_driver_or_raise(driver_id)
    return driver.driver_status

def set_driver_status(
    driver_id:int,
    status:str
) -> None:
    """Called by documents.service when review outcomes change"""
    if status not in DRIVER_STATUSES:
        raise InvalidDriverStatusError(
            f"'{status}' is not valid driver_status (expect one of {DRIVER_STATUSES} )"
        )

    driver = _get_driver_or_raise(driver_id)
    driver.driver_status = status
    db.session.commit()

def deactivate_driver(
    driver_id:int
) -> None:
    driver = _get_driver_or_raise(driver_id)
    driver.is_active = False
    db.session.commit()