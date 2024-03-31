from database import db
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from flask_login import UserMixin


class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(
        primary_key=True, autoincrement=True, nullable=False)
    username: Mapped[str] = mapped_column(unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(80), nullable=False)
    role: Mapped[str] = mapped_column(
        String(80), nullable=False, default='user')
