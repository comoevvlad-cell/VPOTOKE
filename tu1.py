#!/usr/bin/env python3
"""sc_backend.py — серверная логика ситуационного центра (только стандартная библиотека).

Реализовано:
  1. Подпись телеметрии HMAC-SHA256 (hmac.compare_digest), секрет — из переменной окружения
     SENSOR_HMAC_SECRET, проверка location по справочнику sites.csv.
  2. AuditEvent — журнал аудита append-only (цепочка хэшей для обнаружения подмены).
  3. Zone-based RBAC: доступ к инцидентам только в разрешённых зонах (zones="*" — все зоны).
  4. Правила A-5 (дедупликация), A-3 (авто-инцидент), A-4 (зависшие датчики + эскалация).
  5. Строгий жизненный цикл: NEW → ASSIGNED → IN_PROGRESS → CLOSED, без пропусков и без переоткрытия.

Окна: «в течение 5 минут» (A-5) включает границу (<= 5 мин); «дольше 5 минут» (A-4) — строго (> 5 мин).
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import json
import math
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# Имя переменной окружения с секретом подписи датчиков. Секрет НИКОГДА не хранится в коде или в репозитории:
# на сервере его задают в окружении (export SENSOR_HMAC_SECRET=...), минимум 16 символов (см. load_secret).
SECRET_ENV = "SENSOR_HMAC_SECRET"
# Окна правил (timedelta). A-5: повтор в пределах 5 минут включительно = дубликат. A-3: два CRITICAL подряд в окне 15 минут.
# A-4: «нет данных» наступает СТРОГО после 5 минут тишины. INCIDENT_TTL — срок (дедлайн) инцидента: создание + 4 часа.
DEDUP_WINDOW = timedelta(minutes=5)        # A-5
CRITICAL_WINDOW = timedelta(minutes=15)    # A-3
STALE_AFTER = timedelta(minutes=5)         # A-4
INCIDENT_TTL = timedelta(hours=4)          # срок авто-инцидента
ALL_ZONES = "*"
# Хэш-«нулевая точка» для первой записи журнала аудита (у неё нет предыдущей записи).
GENESIS_HASH = "0" * 64

# Статусы жизненного цикла инцидента и таблица разрешённых переходов. Любой переход, которого нет в ALLOWED,
# запрещён: нельзя пропускать шаги (NEW → IN_PROGRESS) и нельзя идти назад; из CLOSED выхода нет.
STATUSES = ("NEW", "ASSIGNED", "IN_PROGRESS", "CLOSED")
ALLOWED = {  # единственно допустимые переходы
    "NEW": ("ASSIGNED",),
    "ASSIGNED": ("IN_PROGRESS",),
    "IN_PROGRESS": ("CLOSED",),
    "CLOSED": (),
}
# Нормы по умолчанию (min, max) по показателям — совпадают с indicators.csv. В боевой версии нормы подгружаются из справочника.
DEFAULT_NORMS = {"temperature": (20.0, 26.0), "humidity": (40.0, 70.0), "ventilation": (0.8, 2.0)}
# Какой тип инцидента создаёт авто-правило A-3 для показателя (температура → инцидент типа temperature и т.д.).
INDICATOR_TO_TYPE = {"temperature": "temperature", "humidity": "humidity", "ventilation": "ventilation"}

# RBAC: права по ролям. Право на ДЕЙСТВИЕ проверяет _require(); доступ к УЧАСТКУ (зоне) — отдельно _zone_guard().
ROLE_PERMS = {
    "dispatcher": {"incident.view", "incident.create", "incident.assign", "incident.status", "incident.deadline"},
    "manager": {"incident.view", "incident.create", "incident.assign", "incident.status", "incident.deadline",
                "escalation.ack", "audit.view"},
    "worker": {"incident.view_own", "incident.take", "incident.close"},
    "admin": {"audit.view", "sites.manage"},
}


# Бизнес-ошибка с машинным кодом (SENSOR_SIGNATURE_INVALID, ZONE_ACCESS_DENIED, LIFECYCLE_* ...).
# API-слой должен превращать code в HTTP-статус (400/403/409), а message показывать пользователю.
class ScError(Exception):
    """Ошибка с машинным кодом (например, SENSOR_SIGNATURE_INVALID)."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message


# ───────────────────────────── время ─────────────────────────────
# Текущее время UTC. В тестах время передаётся параметром now, чтобы результат не зависел от часов машины.
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# datetime → ISO-строка в UTC с «Z» на конце (единый формат времени в аудите и ответах).
def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ISO-строка → datetime в UTC. Принимает 'Z' и смещения; без часового пояса считает время UTC.
def parse_ts(s: str) -> datetime:
    dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp without timezone")
    return dt.astimezone(timezone.utc)


# ───────────────────────── 1. подпись телеметрии ─────────────────────────
# Читает секрет подписи из переменной окружения. Нет переменной или она короче 16 символов → ошибка CONFIG_ERROR:
# сервис не должен стартовать с пустым или слабым секретом.
def load_secret() -> bytes:
    """Секрет только из окружения — в коде и в репозитории его нет."""
    value = os.environ.get(SECRET_ENV, "")
    if len(value) < 16:
        raise ScError("CONFIG_ERROR", f"переменная окружения {SECRET_ENV} не задана или короче 16 символов")
    return value.encode("utf-8")


# Число → строка для подписи БЕЗ лишних нулей (29.0 → '29'). Датчик и сервер обязаны форматировать значение одинаково,
# иначе одна и та же подпись у них получится разной.
def fmt_value(v) -> str:
    """Каноническая запись значения (одинаковая для Python и JS): 29.0 -> '29', 1.69 -> '1.69'."""
    if v is None or v == "":
        return ""
    f = float(v)
    return str(int(f)) if f.is_integer() else repr(f)


# Каноническая строка события для HMAC: event_id|time|location|indicator|value (в байтах UTF-8).
def canonical(event: dict) -> bytes:
    """Подписываемая строка: event_id|time|location|indicator|value."""
    return "|".join([
        str(event.get("event_id", "")), str(event.get("time", "")), str(event.get("location", "")),
        str(event.get("indicator", "")), fmt_value(event.get("value")),
    ]).encode("utf-8")


# Подпись события (hex HMAC-SHA256). Нужна прошивке датчика и тестам; сервер сам её не выпускает.
def sign_event(secret: bytes, event: dict) -> str:
    """Подпись, которую ставит прошивка датчика (нужна тестам и симуляторам)."""
    return hmac.new(secret, canonical(event), hashlib.sha256).hexdigest()


# Проверка подписи входящего события: подпись отсутствует или не совпала → SENSOR_SIGNATURE_INVALID.
# Сравнение через hmac.compare_digest — за постоянное время, чтобы подпись нельзя было подбирать по времени ответа.
def verify_signature(secret: bytes, event: dict) -> None:
    sig = event.get("signature")
    if not isinstance(sig, str) or not sig:
        raise ScError("SENSOR_SIGNATURE_INVALID", "подпись отсутствует")
    try:
        expected = sign_event(secret, event)
    except (TypeError, ValueError):
        raise ScError("INVALID_EVENT", "событие не удалось разобрать")
    if not hmac.compare_digest(expected.encode("ascii"), sig.lower().encode("utf-8", "replace")):
        raise ScError("SENSOR_SIGNATURE_INVALID", "подпись не совпадает")


# Справочник участков из sites.csv (site_id → название и зона). События с участком, которого здесь нет, отклоняются.
class SiteDirectory:
    """Справочник участков из sites.csv: site_id, name, zone."""

    def __init__(self, sites: dict[str, dict]):
        self._sites = dict(sites)

    @classmethod
    def from_csv(cls, path: str) -> "SiteDirectory":
        with open(path, encoding="utf-8-sig", newline="") as f:
            return cls({r["site_id"]: r for r in csv.DictReader(f)})

    def __contains__(self, site_id) -> bool:
        return site_id in self._sites

    def zone_of(self, site_id: str) -> str:
        return self._sites[site_id]["zone"]

    def ids(self):
        return list(self._sites)


# ───────────────────────── 3. роли и зоны ─────────────────────────
# Субъект действия: кто (user_id), роль, доступные зоны (список или '*'), IP. Используется для проверки прав и записывается в аудит.
@dataclass(frozen=True)
class Actor:
    user_id: str
    role: str
    zones: object = field(default_factory=frozenset)  # frozenset[str] либо "*" (старший диспетчер, руководитель)
    ip: str = "0.0.0.0"

    def has_zone(self, zone: str) -> bool:
        return self.zones == ALL_ZONES or zone in self.zones

    def can(self, perm: str) -> bool:
        return perm in ROLE_PERMS.get(self.role, ())


# Служебные «актёры» для записей аудита от самой системы и от шлюза телеметрии.
SYSTEM = Actor("system", "system", ALL_ZONES, "127.0.0.1")
GATEWAY = Actor("sensor-gateway", "system", ALL_ZONES, "127.0.0.1")


# ───────────────────────── 2. журнал аудита ─────────────────────────
# Одна запись журнала аудита (неизменяемая, frozen): event_id, entity_type (incident|alert), entity_id,
# action (created|assigned|status_changed|closed), from/to статус, actor, at, ip, details + prev_hash/hash цепочки.
@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    entity_type: str      # incident | alert
    entity_id: str
    action: str           # created | assigned | status_changed | closed
    from_status: str | None
    to_status: str | None
    actor: str
    at: str               # ISO timestamp
    ip: str
    details: str
    prev_hash: str
    hash: str

    def payload(self) -> str:
        parts = (self.event_id, self.entity_type, self.entity_id, self.action, self.from_status, self.to_status,
                 self.actor, self.at, self.ip, self.details, self.prev_hash)
        return "|".join("" if p is None else str(p) for p in parts)


# Журнал аудита APPEND-ONLY. Запись можно только добавить. Каждая запись содержит хэш предыдущей (prev_hash),
# поэтому изменение/удаление записи в середине рвёт цепочку, и verify() это обнаруживает. update()/delete() всегда отказывают.
# Если указан путь — записи дополнительно дописываются в файл JSONL (журнал переживает перезапуск сервера).
class AuditLog:
    """Append-only: публичного API для изменения и удаления нет, записи неизменяемы (frozen),
    каждая запись хранит хэш предыдущей (verify() находит подмену). С path — дописывание в JSONL."""

    ENTITY_TYPES = ("incident", "alert")
    ACTIONS = ("created", "assigned", "status_changed", "closed")

    def __init__(self, path: str | None = None):
        self._events: list[AuditEvent] = []
        self._lock = threading.RLock()
        self._path = path
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        self._events.append(AuditEvent(**json.loads(line)))
            ok, idx = self.verify()
            if not ok:
                raise ScError("AUDIT_TAMPERED", f"цепочка хэшей нарушена на записи №{idx + 1}")

    # Добавляет запись в конец журнала: проверяет допустимые тип/действие, считает hash от всех полей + prev_hash, пишет в память и файл.
    def append(self, entity_type, entity_id, action, from_status, to_status, actor: Actor, at: datetime,
               details: str = "") -> AuditEvent:
        if entity_type not in self.ENTITY_TYPES or action not in self.ACTIONS:
            raise ScError("AUDIT_INVALID", f"{entity_type}/{action}")
        with self._lock:
            prev = self._events[-1].hash if self._events else GENESIS_HASH
            draft = AuditEvent(f"aud_{len(self._events) + 1:05d}", entity_type, str(entity_id), action, from_status,
                               to_status, actor.user_id, iso(at), actor.ip, details, prev, "")
            ev = AuditEvent(**{**draft.__dict__, "hash": hashlib.sha256(draft.payload().encode("utf-8")).hexdigest()})
            if self._path:
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(ev.__dict__, ensure_ascii=False) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            self._events.append(ev)
            return ev

    def events(self) -> tuple:
        with self._lock:
            return tuple(self._events)

    # Проверка целостности: пересчитывает хэши по порядку. Возвращает (True, None) или (False, номер_первой_испорченной_записи).
    def verify(self) -> tuple[bool, int | None]:
        prev = GENESIS_HASH
        for i, ev in enumerate(self._events):
            if ev.prev_hash != prev or ev.hash != hashlib.sha256(ev.payload().encode("utf-8")).hexdigest():
                return False, i
            prev = ev.hash
        return True, None

    # Явные отказы — чтобы попытка изменить журнал была заметной ошибкой, а не молчаливым no-op.
    # Изменение аудита запрещено по замыслу: всегда AUDIT_APPEND_ONLY.
    def update(self, *a, **k):
        raise ScError("AUDIT_APPEND_ONLY", "изменение записей аудита запрещено")

    # Удаление аудита запрещено по замыслу: всегда AUDIT_APPEND_ONLY.
    def delete(self, *a, **k):
        raise ScError("AUDIT_APPEND_ONLY", "удаление записей аудита запрещено")

    __setitem__ = update
    __delitem__ = delete

    def __len__(self):
        return len(self._events)


# ───────────────────────── модель ─────────────────────────
# Инцидент: id, тип, участок, время создания, ответственный, статус, deadline, источник (manual|auto), описание, связи.
@dataclass
class Incident:
    incident_id: str
    type: str
    location: str
    time: str
    responsible: str
    status: str
    deadline: str
    source: str = "manual"
    description: str = ""
    related_to: str = ""
    alert_id: str = ""


# Алерт по датчику (CRITICAL / STALE): статус OPEN → INCIDENT (привязан к инциденту) → CLOSED, либо ESCALATED/RESOLVED для A-4.
@dataclass
class Alert:
    alert_id: str
    location: str
    indicator: str
    level: str            # CRITICAL | STALE
    value: float | None
    time: str
    status: str           # OPEN | INCIDENT | ESCALATED | ACKNOWLEDGED | RESOLVED | CLOSED
    event_id: str = ""
    incident_id: str = ""


# Показание датчика: время, участок, показатель, значение, норма, статус (NORMAL/WARNING/CRITICAL/STALE/DUPLICATE).
@dataclass
class Reading:
    time: datetime
    location: str
    indicator: str
    value: float | None
    status: str           # NORMAL | WARNING | CRITICAL | STALE | DUPLICATE
    event_id: str = ""


# Эскалация руководителю при «зависшем» датчике (A-4): кому, когда, причина, подтверждена ли.
@dataclass
class Escalation:
    escalation_id: str
    alert_id: str
    location: str
    indicator: str
    to: tuple
    time: str
    reason: str
    ack: bool = False


# Статус значения относительно нормы [lo; hi]: внутри (границы включены) → NORMAL; выход за границу до 20% ширины диапазона → WARNING; больше → CRITICAL.
def classify(value: float, lo: float, hi: float) -> str:
    if lo <= value <= hi:
        return "NORMAL"
    dev = (lo - value) if value < lo else (value - hi)
    return "CRITICAL" if dev > 0.2 * (hi - lo) else "WARNING"


# ЯДРО СЕРВИСА: хранит инциденты, алерты, показания, эскалации и журнал аудита; все операции потокобезопасны (общий замок self._lock).
# Публичные методы: ingest (приём телеметрии), create_incident / assign / transition / follow_up (инциденты),
# check_stale / ack_escalation (A-4), list_incidents. Каждый метод принимает now=... — время можно подставлять в тестах.
class SituationCenter:
    def __init__(self, secret: bytes, sites: SiteDirectory, audit: AuditLog | None = None,
                 norms: dict | None = None, escalation_targets=("manager",)):
        self._secret = secret
        self.sites = sites
        self.audit = audit or AuditLog()
        self.norms = dict(norms or DEFAULT_NORMS)
        self.escalation_targets = tuple(escalation_targets)
        self.incidents: dict[str, Incident] = {}
        self.alerts: dict[str, Alert] = {}
        self.escalations: list[Escalation] = []
        self.readings: list[Reading] = []
        self.stats = {"accepted": 0, "duplicate": 0, "rejected": 0}
        self._seen: set[str] = set()
        self._last_valid: dict[tuple, Reading] = {}
        self._live: dict[tuple, datetime] = {}       # последний «признак жизни» датчика
        self._stale_open: dict[tuple, str] = {}
        self._seq = {"inc": 0, "alr": 0, "esc": 0}
        self._lock = threading.RLock()

    # Фабрика для боевого запуска: секрет берётся из окружения, справочник участков из sites.csv.
    @classmethod
    def from_env(cls, sites_csv: str, audit_path: str | None = None) -> "SituationCenter":
        return cls(load_secret(), SiteDirectory.from_csv(sites_csv), AuditLog(audit_path))

    # ── служебное ──
    # Генератор идентификаторов (inc_001, alr_001, esc_001 ...) с отдельным счётчиком на каждый префикс.
    def _next(self, key: str, prefix: str) -> str:
        self._seq[key] += 1
        return f"{prefix}_{self._seq[key]:03d}"

    # Проверка права роли на действие; нет права → PERMISSION_DENIED.
    def _require(self, actor: Actor, perm: str):
        if not actor.can(perm):
            raise ScError("PERMISSION_DENIED", f"роль «{actor.role}» не имеет права {perm}")

    # Проверка зоны: участок вне зон актёра → ZONE_ACCESS_DENIED. Работает для ЛЮБОЙ операции над инцидентом.
    def _zone_guard(self, actor: Actor, location: str):
        if location not in self.sites:
            raise ScError("UNKNOWN_LOCATION", location)
        if not actor.has_zone(self.sites.zone_of(location)):
            raise ScError("ZONE_ACCESS_DENIED", f"участок {location} ({self.sites.zone_of(location)}) вне ваших зон")

    # Найти инцидент по id или ошибка NOT_FOUND.
    def _get(self, incident_id: str) -> Incident:
        if incident_id not in self.incidents:
            raise ScError("NOT_FOUND", incident_id)
        return self.incidents[incident_id]

    # Короткая обёртка: записать действие в журнал аудита от имени актёра.
    def _audit(self, etype, eid, action, frm, to, actor, at, details=""):
        return self.audit.append(etype, eid, action, frm, to, actor, at, details)

    # ── 3/5. инциденты: зоны и жизненный цикл ──
    # Какие инциденты видит актёр: диспетчер/руководитель — все в своих зонах; рабочий — только назначенные ему (и в его зонах).
    def list_incidents(self, actor: Actor) -> list[Incident]:
        with self._lock:
            if actor.can("incident.view"):
                return [i for i in self.incidents.values() if actor.has_zone(self.sites.zone_of(i.location))]
            if actor.can("incident.view_own"):
                return [i for i in self.incidents.values()
                        if i.responsible == actor.user_id and actor.has_zone(self.sites.zone_of(i.location))]
            raise ScError("PERMISSION_DENIED", "нет права просмотра инцидентов")

    # Создание инцидента. Ручной (source='manual') требует права incident.create; авто-инцидент (A-3) создаёт сама система.
    # Проверяется зона участка. Запись в аудит: created.
    # ИЗМЕНЕНО: deadline теперь можно не передавать (None) — тогда срок считается автоматически как время создания + 4 часа,
    # так же, как в прототипе (situation-center.html). Явно переданный deadline работает как раньше (старые вызовы и тесты не ломаются).
    def create_incident(self, actor: Actor, type: str, location: str, deadline: datetime | None, description: str = "",  # ИЗМЕНЕНО: тип deadline допускает None
                        source: str = "manual", related_to: str = "", alert_id: str = "",
                        now: datetime | None = None) -> Incident:
        with self._lock:
            now = now or utcnow()
            deadline = deadline or (now + INCIDENT_TTL)  # ДОБАВЛЕНО: срок по умолчанию = now + 4 часа (INCIDENT_TTL), если не задан
            if source == "manual":
                self._require(actor, "incident.create")
            self._zone_guard(actor, location)
            inc = Incident(self._next("inc", "inc"), type, location, iso(now), "", "NEW", iso(deadline),
                           source, description, related_to, alert_id)
            self.incidents[inc.incident_id] = inc
            self._audit("incident", inc.incident_id, "created", None, "NEW", actor, now,
                        f"source={source}" + (f"; related_to={related_to}" if related_to else ""))
            return inc

    # Назначение исполнителя: только пользователь с ролью worker и доступом к зоне участка; допустимо, пока статус NEW или ASSIGNED
    # (в работе/закрытый — нельзя). Аудит: assigned. Проверку «рабочий активен» в этой версии делает вызывающий код — в прототипе она есть.
    def assign(self, actor: Actor, incident_id: str, assignee: Actor, now: datetime | None = None) -> Incident:
        with self._lock:
            now = now or utcnow()
            self._require(actor, "incident.assign")
            inc = self._get(incident_id)
            self._zone_guard(actor, inc.location)
            if inc.status == "CLOSED":
                raise ScError("LIFECYCLE_REOPEN_FORBIDDEN", "закрытый инцидент неизменяем — создайте новый")
            if inc.status not in ("NEW", "ASSIGNED"):
                raise ScError("LIFECYCLE_TRANSITION_FORBIDDEN", "переназначение задачи «В работе» запрещено")
            if assignee.role != "worker" or not assignee.has_zone(self.sites.zone_of(inc.location)):
                raise ScError("ZONE_ACCESS_DENIED", "исполнитель не допущен к зоне инцидента")
            frm = inc.status
            inc.responsible, inc.status = assignee.user_id, "ASSIGNED"
            self._audit("incident", incident_id, "assigned", frm, "ASSIGNED", actor, now, f"assignee={assignee.user_id}")
            return inc

    # Смена статуса по строгому циклу. Проверки по порядку: зона → право (рабочий — только свою задачу) → из CLOSED нельзя →
    # переход должен быть в ALLOWED → в ASSIGNED только с исполнителем. При закрытии связанные алерты закрываются. Аудит: status_changed / closed.
    def transition(self, actor: Actor, incident_id: str, to: str, now: datetime | None = None) -> Incident:
        with self._lock:
            now = now or utcnow()
            inc = self._get(incident_id)
            self._zone_guard(actor, inc.location)
            if to not in STATUSES:
                raise ScError("INVALID_STATUS", to)
            if actor.role == "worker":
                self._require(actor, "incident.take" if to == "IN_PROGRESS" else "incident.close")
                if inc.responsible != actor.user_id:
                    raise ScError("PERMISSION_DENIED", "чужой инцидент")
            else:
                self._require(actor, "incident.status")
            frm = inc.status
            if frm == to:
                return inc
            if frm == "CLOSED":
                raise ScError("LIFECYCLE_REOPEN_FORBIDDEN", "закрытый инцидент нельзя открыть заново — создайте новый")
            if to not in ALLOWED[frm]:
                raise ScError("LIFECYCLE_TRANSITION_FORBIDDEN",
                              f"{frm} → {to} запрещён (допустимо: {', '.join(ALLOWED[frm]) or '—'})")
            if to == "ASSIGNED" and not inc.responsible:
                raise ScError("LIFECYCLE_NO_ASSIGNEE", "сначала назначьте исполнителя")
            inc.status = to
            self._audit("incident", incident_id, "closed" if to == "CLOSED" else "status_changed", frm, to, actor, now)
            if to == "CLOSED":
                for a in self.alerts.values():
                    if a.incident_id == incident_id and a.status == "INCIDENT":
                        a.status = "CLOSED"
                        self._audit("alert", a.alert_id, "closed", "INCIDENT", "CLOSED", actor, now,
                                    f"закрыт инцидент {incident_id}")
            return inc

    # Повторный инцидент по ЗАКРЫТОМУ: создаётся новый того же типа/участка со ссылкой related_to (переоткрытие запрещено).
    def follow_up(self, actor: Actor, closed_id: str, deadline: datetime, now: datetime | None = None) -> Incident:
        """Вместо переоткрытия — новый инцидент со ссылкой на закрытый."""
        with self._lock:
            old = self._get(closed_id)
            if old.status != "CLOSED":
                raise ScError("LIFECYCLE_TRANSITION_FORBIDDEN", "повторный инцидент создаётся только по закрытому")
            return self.create_incident(actor, old.type, old.location, deadline,
                                        f"Повторный инцидент по {closed_id}", related_to=closed_id, now=now)

    # ── 1/4. телеметрия и правила ──
    # ПРИЁМ ТЕЛЕМЕТРИИ. Проверки: подпись HMAC → участок есть в sites.csv → показатель известен → event_id не повторялся → время/значение корректны.
    # Любая ошибка = отклонение (счётчик rejected, показание не сохраняется). Затем правила: A-5 (дубликат в 5 минут → DUPLICATE, без алерта),
    # CRITICAL → алерт, A-3 (второй CRITICAL подряд в окне 15 минут → авто-инцидент source=auto без дублей). Возвращает словарь с итогом.
    def ingest(self, raw: dict, now: datetime | None = None) -> dict:
        with self._lock:
            e = dict(raw or {})
            try:
                verify_signature(self._secret, e)
                if e.get("location") not in self.sites:
                    raise ScError("UNKNOWN_LOCATION", f"участок {e.get('location')!r} отсутствует в sites.csv")
                ind = e.get("indicator")
                if ind not in self.norms:
                    raise ScError("UNKNOWN_INDICATOR", str(ind))
                eid = e.get("event_id")
                if not isinstance(eid, str) or not eid:
                    raise ScError("INVALID_EVENT", "нет event_id")
                if eid in self._seen:
                    raise ScError("EVENT_REPLAY", f"event_id {eid} уже обработан")
                try:
                    t = parse_ts(e.get("time"))
                except (TypeError, ValueError):
                    raise ScError("INVALID_EVENT", "некорректное время")
                try:
                    if isinstance(e.get("value"), bool):
                        raise ValueError
                    v = float(e.get("value"))
                    if not math.isfinite(v):
                        raise ValueError
                except (TypeError, ValueError):
                    raise ScError("INVALID_EVENT", "некорректное значение")
            except ScError:
                self.stats["rejected"] += 1
                raise
            now = now or t
            loc = e["location"]
            key = (loc, ind)
            self._seen.add(eid)
            lo, hi = self.norms[ind]
            status = classify(v, lo, hi)
            prev = self._last_valid.get(key)
            self._live[key] = max(self._live.get(key, t), t)          # любое событие — признак жизни датчика

            # A-5: дедупликация (окно от последнего принятого события, граница включена)
            if prev is not None and abs(t - prev.time) <= DEDUP_WINDOW:
                self.readings.append(Reading(t, loc, ind, v, "DUPLICATE", eid))
                self.stats["duplicate"] += 1
                return {"status": "DUPLICATE", "reading_status": "DUPLICATE", "alert": None, "incident": None}

            reading = Reading(t, loc, ind, v, status, eid)
            self.readings.append(reading)
            self._last_valid[key] = reading
            self.stats["accepted"] += 1

            if key in self._stale_open:                              # датчик «ожил»
                a = self.alerts[self._stale_open.pop(key)]
                self._audit("alert", a.alert_id, "status_changed", a.status, "RESOLVED", GATEWAY, now, "данные возобновились")
                a.status = "RESOLVED"

            alert = incident = None
            if status == "CRITICAL":
                alert = Alert(self._next("alr", "alr"), loc, ind, "CRITICAL", v, iso(t), "OPEN", eid)
                self.alerts[alert.alert_id] = alert
                self._audit("alert", alert.alert_id, "created", None, "OPEN", GATEWAY, now, f"{ind}={fmt_value(v)}")
                # A-3: 2 подряд CRITICAL в окне 15 минут → авто-инцидент
                if prev is not None and prev.status == "CRITICAL" and timedelta(0) <= t - prev.time <= CRITICAL_WINDOW:
                    itype = INDICATOR_TO_TYPE[ind]
                    incident = next((i for i in self.incidents.values()
                                     if i.location == loc and i.type == itype and i.status != "CLOSED"), None)
                    if incident is None:
                        incident = self.create_incident(
                            SYSTEM, itype, loc, t + INCIDENT_TTL, f"Авто (A-3): 2 подряд CRITICAL по {ind}",
                            source="auto", alert_id=alert.alert_id, now=now)
                    for a in self.alerts.values():
                        if a.location == loc and a.indicator == ind and a.status == "OPEN":
                            self._audit("alert", a.alert_id, "status_changed", "OPEN", "INCIDENT", SYSTEM, now,
                                        f"привязан к {incident.incident_id}")
                            a.status, a.incident_id = "INCIDENT", incident.incident_id
            return {"status": "ACCEPTED", "reading_status": status, "alert": alert, "incident": incident}

    # A-4: проходит по датчикам, от которых приходили события; тишина строго больше 5 минут и простой ещё не отмечен →
    # показание STALE, алерт ESCALATED и эскалация руководителю (один раз на простой). Вызывается планировщиком, например раз в минуту.
    def check_stale(self, now: datetime | None = None) -> list[Escalation]:
        """A-4: нет данных дольше 5 минут → STALE + эскалация руководителю (один раз на «простой»)."""
        with self._lock:
            now = now or utcnow()
            created = []
            for key, last in self._live.items():
                if key in self._stale_open or now - last <= STALE_AFTER:
                    continue
                loc, ind = key
                minutes = int((now - last).total_seconds() // 60)
                self.readings.append(Reading(now, loc, ind, None, "STALE"))
                alert = Alert(self._next("alr", "alr"), loc, ind, "STALE", None, iso(now), "ESCALATED")
                self.alerts[alert.alert_id] = alert
                self._audit("alert", alert.alert_id, "created", None, "ESCALATED", SYSTEM, now,
                            f"нет данных {minutes} мин (A-4)")
                esc = Escalation(self._next("esc", "esc"), alert.alert_id, loc, ind, self.escalation_targets,
                                 iso(now), f"нет данных {minutes} мин")
                self.escalations.append(esc)
                self._stale_open[key] = alert.alert_id
                created.append(esc)
            return created

    # Руководитель подтверждает эскалацию; алерт ESCALATED → ACKNOWLEDGED (запись в аудит).
    def ack_escalation(self, actor: Actor, escalation_id: str, now: datetime | None = None):
        with self._lock:
            now = now or utcnow()
            self._require(actor, "escalation.ack")
            esc = next((x for x in self.escalations if x.escalation_id == escalation_id), None)
            if esc is None:
                raise ScError("NOT_FOUND", escalation_id)
            if not esc.ack:
                esc.ack = True
                a = self.alerts[esc.alert_id]
                if a.status == "ESCALATED":
                    self._audit("alert", a.alert_id, "status_changed", "ESCALATED", "ACKNOWLEDGED", actor, now)
                    a.status = "ACKNOWLEDGED"
            return esc


# ═════════════════════════ КОНСОЛЬНЫЙ РЕЖИМ (CLI) ═════════════════════════
# ДОБАВЛЕНО: весь блок ниже новый. Он нужен, чтобы запускать те же правила (подпись, A-5, A-3, оценка по норме) из терминала
# на CSV-файлах и получать alerts_out.csv, а также прогонять 5 тест-сценариев командой --selftest. Серверная логика выше НЕ менялась.
import argparse  # ДОБАВЛЕНО: разбор аргументов командной строки (--indicators, --selftest и т.д.)
import sys  # ДОБАВЛЕНО: нужен для кода возврата (sys.exit) и вывода в stdout

# ДОБАВЛЕНО: демонстрационный секрет для CLI. В боевом режиме секрет берётся из SENSOR_HMAC_SECRET (см. load_secret).
# Здесь он нужен только потому, что в CSV нет подписей: CLI играет роль «прошивки датчика» и подписывает строки сам.
DEMO_SECRET = b"demo-secret-only-for-cli-run-0001"  # ДОБАВЛЕНО: минимум 16 символов, иначе load_secret() отверг бы такой ключ
SEVERITY_HEADER = ["alert_id", "at", "location", "indicator", "value", "severity", "action", "note"]  # ДОБАВЛЕНО: колонки alerts_out.csv


# ДОБАВЛЕНО: читает CSV в список словарей (utf-8-sig убирает BOM, если файл сохранён из Excel).
def _read_csv(path: str) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:  # открываем файл только на чтение — исходные данные не меняются
        return list(csv.DictReader(f))  # каждая строка превращается в словарь «колонка → значение»


# ДОБАВЛЕНО: прогоняет показания из indicators.csv через SituationCenter.ingest и возвращает строки для alerts_out.csv и счётчики.
def run_csv(indicators_path: str, sites_path: str, secret: bytes) -> tuple[list[dict], dict]:
    sc = SituationCenter(secret, SiteDirectory.from_csv(sites_path))  # создаём сервис: справочник участков берём из sites.csv
    rows = sorted(_read_csv(indicators_path), key=lambda r: r["time"])  # сортируем по времени: правила A-5/A-3 считают окна по порядку событий
    out: list[dict] = []  # сюда складываем строки результата
    counts = {"rows": len(rows), "accepted": 0, "duplicate": 0, "rejected": 0, "stale_rows": 0, "alerts": 0, "auto_incidents": 0}  # сводка
    for n, r in enumerate(rows, 1):  # идём по строкам, n — порядковый номер для event_id
        if r["value"] == "":  # пустое значение в файле = датчик ничего не передал (правило A-4 в виде данных)
            counts["stale_rows"] += 1  # считаем такие строки отдельно
            out.append({"alert_id": "", "at": r["time"], "location": r["location"], "indicator": r["indicator"], "value": "",
                        "severity": "STALE", "action": "ESCALATED", "note": "нет значения: эскалация руководителю (A-4)"})  # фиксируем STALE и эскалацию
            continue  # в движок такую строку не отправляем: у события без значения нет смысла подписи и оценки
        event = {"event_id": f"csv_{n:04d}", "time": r["time"], "location": r["location"],
                 "indicator": r["indicator"], "value": r["value"]}  # собираем событие так, как его прислал бы датчик
        event["signature"] = sign_event(secret, event)  # ставим подпись HMAC — как это делает прошивка датчика
        try:  # движок может отклонить событие (подпись, участок, повтор, формат)
            res = sc.ingest(event)  # главный вызов: проверки + A-5 + оценка по норме + A-3
        except ScError as e:  # бизнес-ошибка с машинным кодом
            counts["rejected"] += 1  # считаем отказ
            out.append({"alert_id": "", "at": r["time"], "location": r["location"], "indicator": r["indicator"], "value": r["value"],
                        "severity": "", "action": "REJECTED", "note": e.code})  # пишем код ошибки в результат
            continue  # переходим к следующей строке
        if res["status"] == "DUPLICATE":  # A-5: повтор в окне 5 минут
            counts["duplicate"] += 1  # считаем дубль
            out.append({"alert_id": "", "at": r["time"], "location": r["location"], "indicator": r["indicator"], "value": r["value"],
                        "severity": "", "action": "DUPLICATE", "note": "повтор в окне 5 минут (A-5), алерт не создан"})  # дубль виден, но алерта нет
            continue  # следующая строка
        counts["accepted"] += 1  # событие принято
        sev = res["reading_status"]  # NORMAL / WARNING / CRITICAL
        if sev == "NORMAL":  # нормальные показания в отчёт не пишем, чтобы он был читаемым
            continue  # следующая строка
        alert, inc = res["alert"], res["incident"]  # алерт создаётся только для CRITICAL; инцидент — только по A-3
        if alert is not None:  # есть алерт
            counts["alerts"] += 1  # считаем алерты
        if inc is not None:  # сработало правило A-3
            counts["auto_incidents"] += 1  # считаем авто-инциденты
        action = "AUTO_INCIDENT" if inc is not None else ("ALERT_CREATED" if alert is not None else "SHOWN_ON_PANEL")  # что сделала система
        note = f"инцидент {inc.incident_id} (A-3)" if inc is not None else ("" if alert is not None else "WARNING: виден на панели, алерт не создаётся")  # пояснение
        out.append({"alert_id": alert.alert_id if alert else "", "at": r["time"], "location": r["location"], "indicator": r["indicator"],
                    "value": r["value"], "severity": sev, "action": action, "note": note})  # строка результата
    return out, counts  # возвращаем результат и сводку


# ДОБАВЛЕНО: 5 тест-сценариев по заданию: успех, отказ, неверные данные, повтор, таймаут/STALE. Возвращает список (название, ожидание, факт, пройден).
def selftest() -> list[tuple[str, str, str, bool]]:
    secret = b"selftest-secret-0123456789"  # отдельный секрет для самопроверки (≥ 16 символов)
    sites = SiteDirectory({"site_01": {"site_id": "site_01", "name": "Птичник №1", "zone": "zone_A"},
                           "site_02": {"site_id": "site_02", "name": "Птичник №2", "zone": "zone_A"}})  # мини-справочник, чтобы тесты не зависели от файлов
    t0 = parse_ts("2025-11-04T10:00:00Z")  # базовое время сценариев

    def ev(eid: str, t: datetime, loc: str, ind: str, val) -> dict:  # ДОБАВЛЕНО: вспомогательная функция — собирает подписанное событие
        e = {"event_id": eid, "time": iso(t), "location": loc, "indicator": ind, "value": val}  # поля события
        e["signature"] = sign_event(secret, e)  # подпись как у настоящего датчика
        return e  # готовое событие

    results: list[tuple[str, str, str, bool]] = []  # сюда пишем итоги

    # 1) УСПЕХ: корректное подписанное событие принимается, 29 °C при норме 20–26 даёт CRITICAL и алерт
    sc = SituationCenter(secret, sites)  # чистый экземпляр сервиса на каждый сценарий
    r = sc.ingest(ev("t1", t0, "site_02", "temperature", 29), now=t0)  # отправляем событие
    ok = r["status"] == "ACCEPTED" and r["reading_status"] == "CRITICAL" and r["alert"] is not None  # проверяем ожидание
    results.append(("1. Успех", "ACCEPTED, CRITICAL, алерт создан", f'{r["status"]}, {r["reading_status"]}, алерт {"создан" if r["alert"] else "нет"}', ok))  # фиксируем факт

    # 2) ОТКАЗ: подпись подменена — событие должно быть отклонено
    sc = SituationCenter(secret, sites)  # чистый экземпляр
    bad = ev("t2", t0, "site_02", "temperature", 29)  # корректное событие
    bad["signature"] = "0" * 64  # портим подпись
    try:  # ожидаем исключение
        sc.ingest(bad, now=t0)  # отправляем
        got, ok = "принято (ошибка!)", False  # если дошли сюда — защита не сработала
    except ScError as e:  # ожидаемый путь
        got, ok = e.code, e.code == "SENSOR_SIGNATURE_INVALID"  # проверяем код ошибки
    results.append(("2. Отказ (подпись)", "SENSOR_SIGNATURE_INVALID", got, ok))  # фиксируем

    # 3) НЕВЕРНЫЕ ДАННЫЕ: участка нет в справочнике, подпись при этом верная
    sc = SituationCenter(secret, sites)  # чистый экземпляр
    try:  # ожидаем исключение
        sc.ingest(ev("t3", t0, "site_99", "temperature", 29), now=t0)  # неизвестный участок
        got, ok = "принято (ошибка!)", False  # защита не сработала
    except ScError as e:  # ожидаемый путь
        got, ok = e.code, e.code == "UNKNOWN_LOCATION"  # проверяем код
    results.append(("3. Неверные данные", "UNKNOWN_LOCATION", got, ok))  # фиксируем

    # 4) ПОВТОР: второе событие ровно через 5:00 — DUPLICATE, алерт один; тот же event_id — EVENT_REPLAY
    sc = SituationCenter(secret, sites)  # чистый экземпляр
    sc.ingest(ev("t4a", t0, "site_02", "temperature", 29), now=t0)  # первое событие создаёт алерт
    r2 = sc.ingest(ev("t4b", t0 + timedelta(minutes=5), "site_02", "temperature", 29), now=t0 + timedelta(minutes=5))  # граница окна: ровно 5:00
    try:  # повтор того же event_id
        sc.ingest(ev("t4a", t0, "site_02", "temperature", 29), now=t0)  # проигрываем старое событие
        replay = "принято (ошибка!)"  # защита не сработала
    except ScError as e:  # ожидаемый путь
        replay = e.code  # EVENT_REPLAY
    ok = r2["status"] == "DUPLICATE" and len(sc.alerts) == 1 and replay == "EVENT_REPLAY"  # проверяем всё сразу
    results.append(("4. Повтор", "5:00 → DUPLICATE, 1 алерт; тот же event_id → EVENT_REPLAY", f'{r2["status"]}, алертов {len(sc.alerts)}; {replay}', ok))  # фиксируем

    # 5) ТАЙМАУТ/STALE: тишина ровно 5:00 — ещё нет; 5:01 — STALE и эскалация руководителю
    sc = SituationCenter(secret, sites)  # чистый экземпляр
    sc.ingest(ev("t5", t0, "site_01", "humidity", 55), now=t0)  # датчик подал признак жизни
    e1 = sc.check_stale(now=t0 + timedelta(minutes=5))  # ровно 5:00 — граница, STALE ещё нет
    e2 = sc.check_stale(now=t0 + timedelta(minutes=5, seconds=1))  # 5:01 — тишина дольше 5 минут
    ok = len(e1) == 0 and len(e2) == 1 and sc.alerts[e2[0].alert_id].level == "STALE"  # проверяем границу и тип алерта
    results.append(("5. Таймаут / STALE", "5:00 → нет; 5:01 → STALE + эскалация", f"5:00 → {len(e1)}; 5:01 → {len(e2)} эскалация", ok))  # фиксируем
    return results  # отдаём итоги


# ДОБАВЛЕНО: точка входа CLI. Примеры:
#   python sc_backend.py --selftest
#   python sc_backend.py --indicators data/indicators.csv --sites data/sites.csv --out alerts_out.csv
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Ситуационный центр: консольный прогон правил на CSV")  # описание в --help
    ap.add_argument("--indicators", default="data/indicators.csv", help="путь к indicators.csv (только чтение)")  # входные показания
    ap.add_argument("--sites", default="data/sites.csv", help="путь к sites.csv (только чтение)")  # справочник участков
    ap.add_argument("--out", default="alerts_out.csv", help="куда записать результат (новый файл)")  # выходной файл
    ap.add_argument("--selftest", action="store_true", help="прогнать 5 тест-сценариев и показать PASS/FAIL")  # режим самопроверки
    a = ap.parse_args(argv)  # разбираем аргументы
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # чтобы кириллица печаталась и на Windows
    except Exception:
        pass  # если не получилось — просто продолжаем
    if a.selftest:  # режим «5 тестов»
        res = selftest()  # запускаем сценарии
        for name, exp, got, ok in res:  # печатаем таблицу результатов
            print(f'{"PASS" if ok else "FAIL"} | {name} | ожидание: {exp} | факт: {got}')  # одна строка на сценарий
        print(f'Итого: {sum(1 for x in res if x[3])}/{len(res)} пройдено')  # сводка
        return 0 if all(x[3] for x in res) else 1  # код возврата для CI: 0 — всё хорошо
    secret = DEMO_SECRET  # CLI подписывает строки CSV сам: в файле подписей нет
    out, c = run_csv(a.indicators, a.sites, secret)  # основной прогон
    with open(a.out, "w", encoding="utf-8", newline="") as f:  # результат пишем в НОВЫЙ файл, исходный CSV не трогаем
        w = csv.DictWriter(f, fieldnames=SEVERITY_HEADER)  # писатель CSV с заголовком
        w.writeheader()  # строка заголовка
        w.writerows(out)  # все строки результата
    for row in out:  # печатаем то же самое на экран
        print(f'{row["at"]} {row["location"]} {row["indicator"]:<12} {row["value"]:>6} {row["severity"]:<9} {row["action"]:<14} {row["note"]}')  # одна строка
    print(f'\nСтрок: {c["rows"]} | принято: {c["accepted"]} | дублей: {c["duplicate"]} | отклонено: {c["rejected"]} | '
          f'строк STALE: {c["stale_rows"]} | алертов: {c["alerts"]} | авто-инцидентов: {c["auto_incidents"]}')  # итоговая сводка
    print(f"Результат записан в {a.out}")  # подсказка, где файл
    return 0  # успех


if __name__ == "__main__":  # запускается только при прямом вызове файла, при импорте в тестах не выполняется
    sys.exit(main())  # передаём код возврата в shell
