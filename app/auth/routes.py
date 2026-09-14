from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from marshmallow import ValidationError

from app.auth import service
from app.auth.decorators import password_change_required, role_required
from app.auth.exceptions import (
    DuplicateUserError,
    InvalidDriverStatusError,
    NotADriverError,
    UserNotFoundError
)

from auth.schemas import (
    change_password_schema,
    login_schema,
    onboard_driver_schema,
    user_public_schema,
    accept_invite_schema,
    bootstrap_manager_schema,
    invite_manager_schema,
)

auth_bp = Blueprint("auth", __name__)

@auth_bp.post("/onboard_driver")
@role_required("manager")
@password_change_required
def onboard_driver_route():
    try:
        data = onboard_driver_schema.load(request.get_json(silent=True))
    except ValidationError as err:
        return jsonify({"error": "Invalid input", "details": err.messages}), 400

    try:
        driver = service.onboard_driver(name=data["name"], phone=data["phone"])
    except DuplicateUserError as err:
        return jsonify({"error": str(err)}), 409
    except ValueError as err:
        # normalize phone can raise ValueError if the phone number is invalid
        return jsonify({"error": str(err)}), 400

    return jsonify(user_public_schema.dump(driver)), 201

@auth_bp.post("/bootstrap-manager")
def bootstrap_manager_route():
    try:
        data = bootstrap_manager_schema.load(request.get_son(silent=True))
    except ValidationError as err:
        return jsonify({"error":"Invalid input", "details": err.messages}), 400

    try:
        manager = service.bootstrap_first_manager(
            name=data["name"], phone=data["phone"], email=data["email"], password=data["password"]
        )
    except PermissionError as err:
        return jsonify({"error": str(err)}), 403
    except DuplicateUserError as err:
        return jsonify({"error": str(err)}), 409
    except ValueError as err:
        return jsonify({"error": str(err)}), 400

    return jsonify(user_public_schema.dump(manager)), 201

@auth_bp.post("/invite-manager")
@role_required("manager")
@password_change_required
def invite_manager_route():
    try:
        data = invite_manager_schema.load(request.get_json(silent=True))
    except ValidationError as err:
        return jsonify({"error": "Invalid input", "details": err.messages}), 400

    requesting_user_id = int(get_jwt_identity())

    try:
        requesting_user = service.get_user_by_id(requesting_user_id)
        invitee = service.invite_manager(
            name=data["name"],
            phone=data["phone"],
            email = data["email"],
            requesting_user=requesting_user,
        )
    except UserNotFoundError as err:
        return jsonify({"error": str(err)}), 404
    except PermissionError as err:
        return jsonify({"error": str(err)}), 403
    except DuplicateUserError as err:
        return jsonify({"error": str(err)}), 409
    except ValueError as err:
        return jsonify({"error": str(err)}), 400

    return jsonify(user_public_schema.dump(invitee)), 201
    