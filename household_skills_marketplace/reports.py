"""Analytics queries, CSV/PDF exports and PDF receipts."""
import io, csv
from datetime import datetime, date
from db import q
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

TEAL = colors.HexColor("#1F5F6B")


def analytics():
    one = lambda sql, a=(): q(sql, a, one=True)[0]
    months = []
    y, m = date.today().year, date.today().month
    for _ in range(6):
        months.append(f"{y}-{m:02d}")
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    months.reverse()

    def monthly(sql):
        d = {r[0]: r[1] for r in q(sql)}
        return [(mo, d.get(mo, 0)) for mo in months]

    return {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "totals": [
            ("Registered users", one("SELECT COUNT(*) FROM users WHERE role!='admin'")),
            ("Skill providers", one("SELECT COUNT(*) FROM users WHERE role='provider'")),
            ("Clients", one("SELECT COUNT(*) FROM users WHERE role='client'")),
            ("Approved profiles", one("SELECT COUNT(*) FROM profiles WHERE status='approved'")),
            ("Profiles awaiting review", one("SELECT COUNT(*) FROM profiles WHERE status='pending'")),
            ("Bookings", one("SELECT COUNT(*) FROM bookings")),
            ("Completed jobs", one("SELECT COUNT(*) FROM bookings WHERE status='completed'")),
            ("Recorded earnings (R)", round(one("SELECT COALESCE(SUM(final_amount),0) FROM bookings WHERE status='completed'"), 2)),
            ("Open job posts", one("SELECT COUNT(*) FROM jobs WHERE status='open'")),
            ("Job applications", one("SELECT COUNT(*) FROM applications")),
        ],
        "by_category": [tuple(r) for r in q("SELECT category, COUNT(*) FROM profiles WHERE status='approved' GROUP BY category ORDER BY 2 DESC")],
        "by_location": [tuple(r) for r in q("SELECT location, COUNT(*) FROM profiles WHERE status='approved' GROUP BY lower(location) ORDER BY 2 DESC LIMIT 6")],
        "booking_status": [tuple(r) for r in q("SELECT status, COUNT(*) FROM bookings GROUP BY status ORDER BY 2 DESC")],
        "signups": monthly("SELECT strftime('%Y-%m',created_at), COUNT(*) FROM users WHERE role!='admin' GROUP BY 1"),
        "bookings_monthly": monthly("SELECT strftime('%Y-%m',created_at), COUNT(*) FROM bookings GROUP BY 1"),
        "emails": [tuple(r) for r in q("SELECT direction||' / '||status, COUNT(*) FROM emails GROUP BY 1 ORDER BY 2 DESC")],
    }


def analytics_csv(a):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Household Skills Marketplace - analytics", a["generated"]])
    sections = [("Totals", a["totals"]), ("Approved providers by category", a["by_category"]),
                ("Approved providers by location", a["by_location"]), ("Bookings by status", a["booking_status"]),
                ("New users per month", a["signups"]), ("Bookings per month", a["bookings_monthly"]),
                ("E-mail activity", a["emails"])]
    for title, rows in sections:
        w.writerow([]); w.writerow([title])
        for r in rows:
            # neutralise spreadsheet formula injection
            w.writerow([("'" + str(c)) if str(c)[:1] in "=+-@" else c for c in r])
    return buf.getvalue()


def _table(rows, head=None, widths=None):
    data = ([head] if head else []) + [[str(c) for c in r] for r in rows]
    t = Table(data, colWidths=widths, hAlign="LEFT")
    st = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C9D3D0")),
          ("FONTSIZE", (0, 0), (-1, -1), 9), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
          ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    if head:
        st += [("BACKGROUND", (0, 0), (-1, 0), TEAL), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    t.setStyle(TableStyle(st))
    return t


def analytics_pdf(a):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm,
                            title="Marketplace analytics report")
    s = getSampleStyleSheet()
    els = [Paragraph("Household Skills Marketplace", s["Title"]),
           Paragraph(f"Analytics report - generated {a['generated']}", s["Normal"]), Spacer(1, 8)]
    for title, rows, head in [("Overview", a["totals"], ["Measure", "Value"]),
                              ("Approved providers by category", a["by_category"], ["Category", "Providers"]),
                              ("Approved providers by location", a["by_location"], ["Location", "Providers"]),
                              ("Bookings by status", a["booking_status"], ["Status", "Bookings"]),
                              ("New users per month", a["signups"], ["Month", "Users"]),
                              ("Bookings per month", a["bookings_monthly"], ["Month", "Bookings"]),
                              ("E-mail activity", a["emails"], ["Direction / status", "Messages"])]:
        els += [Spacer(1, 10), Paragraph(title, s["Heading2"]),
                _table(rows or [("No data yet", "")], head, [90*mm, 40*mm])]
    doc.build(els)
    return buf.getvalue()


def receipt_pdf(b):
    """b: joined booking row (dict-like) with client_name, provider_name, etc."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm, topMargin=18*mm,
                            title=f"Receipt {b['receipt_no']}")
    s = getSampleStyleSheet()
    amt = b["final_amount"] if b["final_amount"] is not None else (b["quoted_amount"] or 0)
    els = [Paragraph("Household Skills Marketplace", s["Title"]), Paragraph("SERVICE RECEIPT", s["Heading2"]),
           Spacer(1, 6),
           _table([("Receipt no.", b["receipt_no"]), ("Issued", str(b["completed_at"] or "")[:10]),
                   ("Client", b["client_name"]), ("Service provider", b["provider_name"]),
                   ("Category", b["category"] or "-"), ("Service date", b["service_date"]),
                   ("Booking reference", f"#{b['id']}")], None, [45*mm, 115*mm]),
           Spacer(1, 10), Paragraph("Work carried out", s["Heading3"]),
           Paragraph(str(b["description"]).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), s["Normal"]),
           Spacer(1, 10), _table([("TOTAL AGREED", f"R {amt:,.2f}")], None, [45*mm, 115*mm]),
           Spacer(1, 14),
           Paragraph("Payment is arranged directly between client and provider. This receipt records the "
                     "agreed amount for the completed job; the platform does not process payments (version 1).",
                     s["Italic"])]
    doc.build(els)
    return buf.getvalue()
