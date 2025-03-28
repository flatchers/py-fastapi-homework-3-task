from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import delete
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from database.validators.accounts import validate_password_strength
from exceptions import BaseSecurityError, TokenExpiredError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, TokenRefreshResponseSchema, \
    TokenRefreshRequestSchema, PasswordResetCompleteRequestSchema, MessageResponseSchema, PasswordResetRequestSchema, \
    UserActivationRequestSchema, UserLoginResponseSchema, UserLoginRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        statement = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
        user = statement.scalar_one_or_none()

        if user:
            raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")

        statement = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        result = await db.execute(statement)
        user_group = result.scalars().first()

        if not user_group:
            raise HTTPException(status_code=500, detail="Default user group not found")

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id
        )

        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        token = ActivationTokenModel(user_id=new_user.id)
        db.add(token)
        await db.commit()

        return new_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema, status_code=200)
async def activate_user(schema: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):

    statement = select(UserModel).where(UserModel.email == schema.email)
    result = await db.execute(statement)
    user = result.scalar_one_or_none()
    expired_statement = select(ActivationTokenModel).where(ActivationTokenModel.token == schema.token)
    expired_result = await db.execute(expired_statement)
    is_expired = expired_result.scalar_one_or_none()

    if not is_expired:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if not user:
        raise HTTPException(status_code=400, detail="User with this email does not exist.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    if is_expired.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    user.is_active = True
    await db.delete(is_expired)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=200)
async def password_reset_request(request: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    statement = await db.execute(select(UserModel).where(UserModel.email == request.email))
    user = statement.scalar_one_or_none()

    if user and user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        await db.commit()

        new_token = PasswordResetTokenModel(user_id=user.id)
        db.add(new_token)
        await db.commit()
        print(new_token)

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=200)
async def password_reset_complete(request: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    current_time = datetime.now(timezone.utc)
    statement = await db.execute(select(UserModel).filter(UserModel.email == str(request.email)))
    user = statement.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        password_statement = select(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id)
        password_result = await db.execute(password_statement)
        password_reset = password_result.scalar_one_or_none()
        if not password_reset:
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        if password_reset.expires_at.replace(tzinfo=timezone.utc) < current_time:
            delete_query = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
            await db.execute(delete_query)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        if password_reset.token != request.token:
            delete_query = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
            await db.execute(delete_query)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        if (
                user
                and password_reset.token == request.token
                and password_reset.expires_at.replace(tzinfo=timezone.utc) >= current_time
        ):
            user._hashed_password = hash_password(validate_password_strength(request.password))
            await db.commit()
            return {"message": "Password reset successfully."}
        else:
            await db.rollback()
            raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
        request: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    statement = await db.execute(select(UserModel).where(UserModel.email == request.email))
    user = statement.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.verify_password(request.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        if user.email == request.email and user.verify_password(request.password):
            access_token = jwt_manager.create_access_token(
                data={"sub": user.email, "user_id": user.id},
            )

            refresh_token = jwt_manager.create_refresh_token(
                data={"sub": user.email, "user_id": user.id},
            )
            create_refresh_token = RefreshTokenModel.create(
                user_id=user.id,
                days_valid=settings.LOGIN_TIME_DAYS,
                token=refresh_token
            )
            db.add(create_refresh_token)
            await db.commit()
            await db.refresh(create_refresh_token)

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer"
            }

        else:
            raise HTTPException(status_code=500, detail="An error occurred while processing the request.")
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=200)
async def access_token_refresh(
        request: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    statement = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == request.refresh_token))
    refresh = statement.scalar_one_or_none()
    try:
        jwt_manager.decode_refresh_token(request.refresh_token)
    except TokenExpiredError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    if not refresh:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    jwt_obj = jwt_manager.decode_refresh_token(refresh.token)

    if not jwt_obj or "sub" not in jwt_obj:
        raise HTTPException(status_code=404, detail="User not found.")

    user_statement = await db.execute(select(UserModel).where(UserModel.email == jwt_obj["sub"]))
    user = user_statement.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    try:
        new_access_token = jwt_manager.create_access_token(
            data={"sub": user.email, "user_id": user.id}
        )
        return {"access_token": new_access_token}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
