from pydantic import BaseModel
from typing import List, Optional


# Pydantic models

class URL(BaseModel):
    longURL: str
    apiKey: Optional[str] = None
    shortURL: Optional[str] = None
    tag: Optional[str] = None
    userId: Optional[str] = None


class CreateShortURLPayload(BaseModel):
    longURL: str
    apiKey: str
    tag: Optional[str] = None
    userId: Optional[str] = None


class ResponseModel(BaseModel):
    url: Optional[str] = None
    message: str
    success: Optional[bool] = None


class User(BaseModel):
    name: str
    email: str
    password: str
    apiKey: Optional[str] = None
    consumed: Optional[int] = None
    provider: Optional[int] = None


class SignupPayload(BaseModel):
    name: str
    email: str
    password: str


class LoginPayload(BaseModel):
    email: str
    password: str


class UserInDB(User):
    id: str
    apiKey: str
    name: str


class UserResponseModal(User):
    id: str
