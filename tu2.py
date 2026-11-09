#!/usr/bin/env python3
"""test_sc_backend.py — 32 автотеста серверного модуля sc_backend.py (только стандартная библиотека, unittest).

Запуск:  python -m unittest test_sc_backend -v     (из папки, где лежат sc_backend.py и data/)
Группы:  подпись и приём (8) · оценка по норме и совпадение с CSV (6) · A-5 и A-3 (5) · A-4 (4) ·
         зоны и роли (4) · жизненный цикл (3) · журнал аудита (2) — всего 32.
Время в тестах всегда передаётся параметром now, поэтому результат не зависит от часов компьютера.
"""
import csv  # чтение CSV для тестов «сервер = данные»
import os  # пути к файлам данных и временный файл аудита
import tempfile  # временная папка для JSONL-журнала
import unittest  # стандартный тестовый фреймворк Python
from datetime import timedelta  # сдвиги времени для проверки окон 5:00 и 15:00

import sc_backend as b  # тестируемый модуль

HERE = os.path.dirname(os.path.abspath(__file__))  # папка с тестом
DATA = os.path.join(HERE, "data")  # папка с CSV (файлы только читаются)
SECRET = b"test-secret-0123456789"  # тестовый секрет подписи (не меньше 16 символов)
T0 = b.parse_ts("2025-11-04T10:00:00Z")  # базовое время всех сценариев
SITES = b.SiteDirectory({  # мини-справочник: три участка в трёх зонах
    "site_01": {"site_id": "site_01", "name": "Птичник №1", "zone": "zone_A"},
    "site_03": {"site_id": "site_03", "name": "Птичник №3", "zone": "zone_B"},
    "site_05": {"site_id": "site_05", "name": "Кормоцех", "zone": "zone_C"},
})
DISP_A = b.Actor("e_003", "dispatcher", frozenset({"zone_A"}))  # диспетчер только зоны A
DISP_ALL = b.Actor("e_002", "dispatcher", b.ALL_ZONES)  # dispatcher со всеми зонами
MANAGER = b.Actor("e_005", "manager", b.ALL_ZONES)  # руководитель
ADMIN = b.Actor("e_001", "admin", b.ALL_ZONES)  # администратор
WORKER_A = b.Actor("e_102", "worker", frozenset({"zone_A"}))  # рабочий зоны A
WORKER_A2 = b.Actor("e_103", "worker", frozenset({"zone_A"}))  # второй рабочий зоны A


def ev(eid, t, loc="site_01", ind="temperature", val=23, secret=SECRET):
    """Подписанное событие датчика, как его отправила бы прошивка."""
    e = {"event_id": eid, "time": b.iso(t), "location": loc, "indicator": ind, "value": val}  # поля события
    e["signature"] = b.sign_event(secret, e)  # подпись HMAC-SHA256
    return e  # готовое событие


def center(audit=None):
    """Чистый экземпляр сервиса на каждый тест."""
    return b.SituationCenter(SECRET, SITES, audit=audit)


class T1Signature(unittest.TestCase):
    """Подпись и проверки при приёме события — 8 тестов."""

    def test_01_valid_event_accepted(self):  # корректное подписанное событие принимается
        r = center().ingest(ev("e1", T0), now=T0)
        self.assertEqual(r["status"], "ACCEPTED")

    def test_02_missing_signature_rejected(self):  # нет подписи → SENSOR_SIGNATURE_INVALID
        e = ev("e1", T0); del e["signature"]
        with self.assertRaises(b.ScError) as cm:
            center().ingest(e, now=T0)
        self.assertEqual(cm.exception.code, "SENSOR_SIGNATURE_INVALID")

    def test_03_tampered_value_rejected(self):  # подменили значение после подписи → отказ
        e = ev("e1", T0, val=23); e["value"] = 40
        with self.assertRaises(b.ScError) as cm:
            center().ingest(e, now=T0)
        self.assertEqual(cm.exception.code, "SENSOR_SIGNATURE_INVALID")

    def test_04_tampered_location_rejected(self):  # подменили участок после подписи → отказ
        e = ev("e1", T0, loc="site_01"); e["location"] = "site_03"
        with self.assertRaises(b.ScError) as cm:
            center().ingest(e, now=T0)
        self.assertEqual(cm.exception.code, "SENSOR_SIGNATURE_INVALID")

    def test_05_wrong_secret_rejected(self):  # подписано чужим ключом → отказ
        with self.assertRaises(b.ScError) as cm:
            center().ingest(ev("e1", T0, secret=b"other-secret-0123456789"), now=T0)
        self.assertEqual(cm.exception.code, "SENSOR_SIGNATURE_INVALID")

    def test_06_unknown_location_rejected_and_logged(self):  # участка нет в справочнике → UNKNOWN_LOCATION + запись в системный журнал
        sc = center()
        with self.assertRaises(b.ScError) as cm:
            sc.ingest(ev("e1", T0, loc="site_99"), now=T0)
        self.assertEqual(cm.exception.code, "UNKNOWN_LOCATION")
        self.assertEqual(sc.system_log[-1]["code"], "UNKNOWN_LOCATION")
        self.assertEqual(sc.stats["rejected"], 1)

    def test_07_replay_event_id_rejected(self):  # тот же event_id второй раз → EVENT_REPLAY
        sc = center(); e = ev("e1", T0)
        sc.ingest(e, now=T0)
        with self.assertRaises(b.ScError) as cm:
            sc.ingest(e, now=T0)
        self.assertEqual(cm.exception.code, "EVENT_REPLAY")

    def test_08_invalid_time_and_value_rejected(self):  # время без часового пояса и NaN → INVALID_EVENT
        sc = center()
        e = {"event_id": "e1", "time": "2025-11-04T10:00:00", "location": "site_01", "indicator": "temperature", "value": 23}
        e["signature"] = b.sign_event(SECRET, e)
        with self.assertRaises(b.ScError) as cm:
            sc.ingest(e, now=T0)
        self.assertEqual(cm.exception.code, "INVALID_EVENT")
        with self.assertRaises(b.ScError) as cm2:
            sc.ingest(ev("e2", T0, val="nan"), now=T0)
        self.assertEqual(cm2.exception.code, "INVALID_EVENT")


class T2NormAndCsv(unittest.TestCase):
    """Оценка по норме и совпадение сервера с CSV — 6 тестов."""

    def test_09_lower_boundary_is_normal(self):  # ровно norm_min → NORMAL (в CSV humidity 40.0 = NORMAL)
        self.assertEqual(b.classify(40.0, 40.0, 70.0), "NORMAL")

    def test_10_upper_boundary_is_warning(self):  # ровно norm_max → WARNING (в CSV temperature 26.0 = WARNING)
        self.assertEqual(b.classify(26.0, 20.0, 26.0), "WARNING")

    def test_11_warning_and_critical_thresholds(self):  # 20% ширины нормы: 27.2 ещё WARNING, 27.3 уже CRITICAL; снизу так же
        self.assertEqual(b.classify(27.2, 20.0, 26.0), "WARNING")
        self.assertEqual(b.classify(27.3, 20.0, 26.0), "CRITICAL")
        self.assertEqual(b.classify(18.8, 20.0, 26.0), "WARNING")
        self.assertEqual(b.classify(18.7, 20.0, 26.0), "CRITICAL")

    def test_12_every_csv_row_matches_server(self):  # каждая строка indicators.csv: статус сервера = статус в файле
        with open(os.path.join(DATA, "indicators.csv"), encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 100)
        for r in rows:
            got = "STALE" if r["value"] == "" else b.classify(float(r["value"]), float(r["norm_min"]), float(r["norm_max"]))
            self.assertEqual(got, r["status"], msg=f"{r['time']} {r['location']} {r['indicator']}={r['value']}")

    def test_13_norms_loaded_from_csv(self):  # нормы берутся из indicators.csv и совпадают с нормами сервиса
        self.assertEqual(b.norms_from_csv(os.path.join(DATA, "indicators.csv")), b.DEFAULT_NORMS)

    def test_14_incidents_loaded_from_csv_as_is(self):  # incidents.csv грузится без пересчёта статусов и сроков
        sc = b.SituationCenter(SECRET, b.SiteDirectory.from_csv(os.path.join(DATA, "sites.csv")))
        path = os.path.join(DATA, "incidents.csv")
        self.assertEqual(sc.load_incidents_csv(path), 100)
        with open(path, encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f):
                inc = sc.incidents[r["incident_id"]]
                self.assertEqual((inc.status, inc.responsible, inc.deadline), (r["status"], r["responsible"], r["deadline"]))
        new = sc.create_incident(DISP_ALL, "other", "site_01", None, now=T0)  # новый номер идёт после inc_100
        self.assertEqual(new.incident_id, "inc_101")


class T3DedupAndAutoIncident(unittest.TestCase):
    """A-5 дедупликация и A-3 авто-инцидент — 5 тестов."""

    def test_15_dedup_exactly_5_00_is_duplicate(self):  # повтор ровно через 5:00 → DUPLICATE, второго алерта нет
        sc = center()
        sc.ingest(ev("e1", T0, val=29), now=T0)
        r = sc.ingest(ev("e2", T0 + timedelta(minutes=5), val=29))
        self.assertEqual(r["status"], "DUPLICATE")
        self.assertEqual(len(sc.alerts), 1)

    def test_16_after_5_01_not_duplicate(self):  # через 5:01 событие уже новое
        sc = center()
        sc.ingest(ev("e1", T0), now=T0)
        r = sc.ingest(ev("e2", T0 + timedelta(minutes=5, seconds=1)))
        self.assertEqual(r["status"], "ACCEPTED")

    def test_17_two_critical_within_15_creates_auto_incident(self):  # два CRITICAL подряд через 15:00 → авто-инцидент
        sc = center()
        sc.ingest(ev("e1", T0, val=29), now=T0)
        r = sc.ingest(ev("e2", T0 + timedelta(minutes=15), val=29))
        self.assertIsNotNone(r["incident"])
        self.assertEqual(r["incident"].source, "auto")
        self.assertEqual(r["incident"].deadline, b.iso(T0 + timedelta(minutes=15, hours=4)))  # срок: событие + 4 часа

    def test_18_critical_after_15_01_no_incident(self):  # второй CRITICAL позже 15:00 → инцидента нет
        sc = center()
        sc.ingest(ev("e1", T0, val=29), now=T0)
        r = sc.ingest(ev("e2", T0 + timedelta(minutes=15, seconds=1), val=29))
        self.assertIsNone(r["incident"])

    def test_19_no_second_incident_while_open(self):  # пока авто-инцидент открыт, второй по датчику не создаётся
        sc = center()
        sc.ingest(ev("e1", T0, val=29), now=T0)
        r1 = sc.ingest(ev("e2", T0 + timedelta(minutes=10), val=29))
        r2 = sc.ingest(ev("e3", T0 + timedelta(minutes=20), val=29))
        self.assertEqual(r1["incident"].incident_id, r2["incident"].incident_id)
        self.assertEqual(len(sc.incidents), 1)


class T4Stale(unittest.TestCase):
    """A-4 зависший датчик — 4 теста."""

    def test_20_silence_exactly_5_00_not_stale(self):  # тишина ровно 5:00 → ещё не STALE
        sc = center(); sc.ingest(ev("e1", T0), now=T0)
        self.assertEqual(sc.check_stale(now=T0 + timedelta(minutes=5)), [])

    def test_21_silence_5_01_stale_and_escalation(self):  # тишина 5:01 → STALE и эскалация руководителю
        sc = center(); sc.ingest(ev("e1", T0), now=T0)
        esc = sc.check_stale(now=T0 + timedelta(minutes=5, seconds=1))
        self.assertEqual(len(esc), 1)
        self.assertEqual(esc[0].to, ("manager",))
        self.assertEqual(sc.alerts[esc[0].alert_id].level, "STALE")

    def test_22_one_escalation_per_idle(self):  # повторная проверка того же простоя новую эскалацию не создаёт
        sc = center(); sc.ingest(ev("e1", T0), now=T0)
        sc.check_stale(now=T0 + timedelta(minutes=6))
        self.assertEqual(sc.check_stale(now=T0 + timedelta(minutes=30)), [])
        self.assertEqual(len(sc.escalations), 1)

    def test_23_data_resumed_alert_resolved(self):  # данные вернулись → алерт STALE получает RESOLVED
        sc = center(); sc.ingest(ev("e1", T0), now=T0)
        esc = sc.check_stale(now=T0 + timedelta(minutes=6))
        sc.ingest(ev("e2", T0 + timedelta(minutes=7)))
        self.assertEqual(sc.alerts[esc[0].alert_id].status, "RESOLVED")


class T5ZonesRoles(unittest.TestCase):
    """Зоны и роли — 4 теста."""

    def test_24_dispatcher_other_zone_denied(self):  # диспетчер зоны A не может создать инцидент в зоне C
        with self.assertRaises(b.ScError) as cm:
            center().create_incident(DISP_A, "other", "site_05", None, now=T0)
        self.assertEqual(cm.exception.code, "ZONE_ACCESS_DENIED")

    def test_25_all_zones_dispatcher_sees_everything(self):  # dispatcher с zones="*" видит все зоны, диспетчер A — только свою
        sc = center()
        for loc in ("site_01", "site_03", "site_05"):
            sc.create_incident(DISP_ALL, "other", loc, None, now=T0)
        self.assertEqual(len(sc.list_incidents(DISP_ALL)), 3)
        self.assertEqual([i.location for i in sc.list_incidents(DISP_A)], ["site_01"])

    def test_26_worker_sees_only_own(self):  # рабочий видит только назначенные ему задачи
        sc = center()
        i1 = sc.create_incident(DISP_A, "other", "site_01", None, now=T0)
        sc.create_incident(DISP_A, "other", "site_01", None, now=T0)
        sc.assign(DISP_A, i1.incident_id, WORKER_A, now=T0)
        self.assertEqual([i.incident_id for i in sc.list_incidents(WORKER_A)], [i1.incident_id])

    def test_27_admin_and_escalation_permissions(self):  # админ не видит инциденты; подтвердить эскалацию может только руководитель
        sc = center()
        with self.assertRaises(b.ScError):
            sc.list_incidents(ADMIN)
        sc.ingest(ev("e1", T0), now=T0)
        esc = sc.check_stale(now=T0 + timedelta(minutes=6))[0]
        with self.assertRaises(b.ScError) as cm:
            sc.ack_escalation(DISP_ALL, esc.escalation_id, now=T0)
        self.assertEqual(cm.exception.code, "PERMISSION_DENIED")
        sc.ack_escalation(MANAGER, esc.escalation_id, now=T0)
        self.assertEqual(sc.alerts[esc.alert_id].status, "ACKNOWLEDGED")


class T6Lifecycle(unittest.TestCase):
    """Жизненный цикл инцидента — 3 теста."""

    def test_28_full_cycle_and_default_deadline(self):  # NEW → ASSIGNED → IN_PROGRESS → CLOSED; срок по умолчанию +4 часа
        sc = center()
        inc = sc.create_incident(DISP_A, "temperature", "site_01", None, now=T0)
        self.assertEqual(inc.deadline, b.iso(T0 + timedelta(hours=4)))
        sc.assign(DISP_A, inc.incident_id, WORKER_A, now=T0)
        sc.transition(WORKER_A, inc.incident_id, "IN_PROGRESS", now=T0)
        sc.transition(WORKER_A, inc.incident_id, "CLOSED", now=T0)
        self.assertEqual(inc.status, "CLOSED")

    def test_29_skip_and_foreign_task_forbidden(self):  # NEW → CLOSED запрещён; чужой рабочий не может взять задачу
        sc = center()
        inc = sc.create_incident(DISP_A, "other", "site_01", None, now=T0)
        with self.assertRaises(b.ScError) as cm:
            sc.transition(DISP_A, inc.incident_id, "CLOSED", now=T0)
        self.assertEqual(cm.exception.code, "LIFECYCLE_TRANSITION_FORBIDDEN")
        sc.assign(DISP_A, inc.incident_id, WORKER_A, now=T0)
        with self.assertRaises(b.ScError) as cm2:
            sc.transition(WORKER_A2, inc.incident_id, "IN_PROGRESS", now=T0)
        self.assertEqual(cm2.exception.code, "PERMISSION_DENIED")

    def test_30_reopen_forbidden_follow_up_created(self):  # закрытый нельзя открыть; вместо этого новый со ссылкой
        sc = center()
        inc = sc.create_incident(DISP_A, "other", "site_01", None, now=T0)
        sc.assign(DISP_A, inc.incident_id, WORKER_A, now=T0)
        sc.transition(WORKER_A, inc.incident_id, "IN_PROGRESS", now=T0)
        sc.transition(WORKER_A, inc.incident_id, "CLOSED", now=T0)
        with self.assertRaises(b.ScError) as cm:
            sc.transition(DISP_A, inc.incident_id, "IN_PROGRESS", now=T0)
        self.assertEqual(cm.exception.code, "LIFECYCLE_REOPEN_FORBIDDEN")
        nxt = sc.follow_up(DISP_A, inc.incident_id, None, now=T0)
        self.assertEqual((nxt.status, nxt.related_to), ("NEW", inc.incident_id))


class T7Audit(unittest.TestCase):
    """Журнал аудита — 2 теста."""

    def test_31_append_only_and_hash_chain(self):  # изменить или удалить запись нельзя; правка в середине ломает цепочку
        sc = center()
        inc = sc.create_incident(DISP_A, "other", "site_01", None, now=T0)
        sc.assign(DISP_A, inc.incident_id, WORKER_A, now=T0)
        self.assertEqual(sc.audit.verify(), (True, None))
        with self.assertRaises(b.ScError):
            sc.audit.update(0, None)
        with self.assertRaises(b.ScError):
            del sc.audit[0]
        first = sc.audit._events[0]  # имитация взлома: подменяем поле первой записи напрямую
        sc.audit._events[0] = b.AuditEvent(**{**first.__dict__, "actor": "hacker"})
        self.assertEqual(sc.audit.verify(), (False, 0))

    def test_32_jsonl_survives_restart_and_detects_tamper(self):  # журнал в JSONL переживает перезапуск; правка файла даёт AUDIT_TAMPERED
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            sc = center(audit=b.AuditLog(path))
            inc = sc.create_incident(DISP_A, "other", "site_01", None, now=T0)
            sc.assign(DISP_A, inc.incident_id, WORKER_A, now=T0)
            self.assertEqual(len(b.AuditLog(path)), 2)  # после «перезапуска» обе записи на месте
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
            with open(path, "w", encoding="utf-8") as f:
                f.write(lines[0].replace('"e_003"', '"e_999"'))  # подменили автора первой записи
                f.writelines(lines[1:])
            with self.assertRaises(b.ScError) as cm:
                b.AuditLog(path)
            self.assertEqual(cm.exception.code, "AUDIT_TAMPERED")


if __name__ == "__main__":
    unittest.main(verbosity=2)