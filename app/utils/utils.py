from flask import request
from datetime import datetime
from app import db
from app.models import LogAktivitas

def log_activity(user_id, aktivitas):
    ip = request.remote_addr
    ua = request.user_agent.string
    new_log = LogAktivitas(
        user_id=user_id,
        aktivitas=aktivitas,
        ip_address=ip,
        user_agent=ua,
        timestamp=datetime.utcnow()
    )
    db.session.add(new_log)
    db.session.commit()