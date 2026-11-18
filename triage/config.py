"""All rule vocabularies live here so the rules can be tuned without touching logic.

EDIT TRUSTED_DOMAINS to your institution's real email domain(s).
"""

# Domains treated as "official". Used for (a) lowering the threat score slightly and
# (b) detecting look-alike domains such as "woxsen-edu.in".
# NOTE: a matching domain does NOT prove the sender is genuine (headers can be spoofed).
TRUSTED_DOMAINS = ["woxsen.edu.in"]

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com", "rediffmail.com",
    "proton.me", "protonmail.com", "icloud.com", "aol.com", "mail.com",
}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rb.gy", "ow.ly", "shorturl.at"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "tk", "ml", "gq", "cf", "ga", "work", "loan", "zip", "country"}

# ---------------------------------------------------------------- threat vocab
PAYMENT_WORDS = [
    "registration fee", "processing fee", "security deposit", "refundable", "payment", "pay",
    "deposit", "transfer", "send money", "upi", "bank details", "gift card", "wire",
]
URGENCY_WORDS = [
    "urgent", "urgently", "immediately", "act now", "last chance", "asap", "right away",
    "within 24 hours", "within 12 hours", "within 48 hours", "expires today", "final warning", "hurry",
]
TOO_GOOD_WORDS = [
    "guaranteed", "100% placement", "100% guaranteed", "no interview", "no experience needed",
    "earn from home", "lottery", "you have won", "selected without",
]
CREDENTIAL_WORDS = [
    "password", "otp", "one time password", "verify your account", "confirm your credentials",
    "log in", "login", "sign in", "account suspended", "account will be suspended",
    "account will be blocked", "update your details", "cvv", "pin number",
]
OFFICIAL_CLAIMS = [
    "placement cell", "examination cell", "exam cell", "registrar", "university", "dean",
    "head of department", "hod", "admin office", "college administration", "principal",
]

# ------------------------------------------------------------- priority vocab
# A trailing "*" means "any word starting with this stem".
HIGH_PRIORITY_WORDS = [
    "exam*", "hall ticket", "admit card", "end-semester", "mid-semester", "timetable", "datesheet",
    "last date", "deadline", "registration closes", "placement drive", "interview", "shortlisted",
    "result*", "fee due", "mandatory", "attendance shortage", "detained", "viva",
]
URGENCY_PRIORITY_WORDS = ["urgent*", "immediately", "asap", "action required", "reminder", "last chance", "important", "within"]
LOW_PRIORITY_WORDS = ["newsletter", "unsubscribe", "weekly digest", "digest", "promotion*", "discount", "no action required", "fyi", "for your information"]

# ----------------------------------------------------------------- topic vocab
TOPICS = {
    "Academics": [
        "exam*", "timetable", "hall ticket", "assignment*", "syllabus", "lecture*", "class*", "semester",
        "faculty", "course*", "grade*", "marks", "result*", "lab", "quiz*", "attendance", "professor",
        "internal assessment", "viva", "datesheet", "academic*",
    ],
    "Internship/Placement": [
        "internship*", "placement*", "recruit*", "drive", "job*", "offer letter", "stipend", "interview*",
        "resume", "hiring", "shortlisted", "career*", "ctc", "offer",
    ],
    "Hostel": ["hostel*", "warden", "mess", "room*", "laundry", "curfew", "roommate*", "accommodation", "inmate*"],
    "Clubs/Events": [
        "club*", "event*", "fest", "festival", "workshop*", "hackathon*", "competition*", "seminar*",
        "cultural", "sports", "volunteer*", "society", "concert", "webinar*", "meetup",
    ],
    "Administrative": [
        "fee", "fees", "scholarship*", "certificate*", "id card", "bonafide", "library", "transport",
        "office", "registrar", "admission*", "document*", "form", "enrolment", "enrollment", "refund*", "transcript",
    ],
}

# --------------------------------------------------------------- timetable vocab
EXAM_TERMS = ["exam*", "examination*", "test", "paper", "viva", "end-semester", "mid-semester"]
SCHEDULE_TERMS = ["timetable", "time table", "datesheet", "date sheet", "schedule*", "rescheduled", "postponed", "preponed", "revised"]
REVISION_TERMS = ["rescheduled", "postponed", "preponed", "revised", "shifted", "changed", "updated schedule"]

# ------------------------------------------------------------------- thresholds
THREAT_SUSPICIOUS = 5
THREAT_CAUTION = 2
PRIORITY_HIGH = 3
PRIORITY_LOW = -1
TOPIC_MIN_SCORE = 2  # one weak body keyword alone is not enough to name a topic
