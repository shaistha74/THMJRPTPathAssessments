# THMJRPTPATH

A collection of my solved TryHackMe rooms and challenges — writeups, methodology notes, and interview-prep summaries for each. Built while working through the Jr Penetration Tester path.

> **Note:** No live flag values are posted here, in line with TryHackMe's terms of use. Writeups focus on methodology, tooling, and reasoning rather than final answers.

## 📂 Structure

```
THMJRPTPATH/
├── README.md
└── rooms/
    └── walking-an-application.md
```

Each room gets its own file under `rooms/`, containing:
- **Objective** — what the room covers
- **Methodology** — the approach/tools used, step by step
- **Key techniques & cheat sheet** — reusable notes for future engagements
- **Findings summary** — vulnerability classes identified, framed like a real assessment
- **Interview Q&A** — talking points drawn from the room's concepts

## ✅ Rooms Completed

| Room | Category | Key Topics |
|---|---|---|
| [Walking An Application](rooms/walking-an-application.md) | Web App Security — Manual Recon | Page source review, DOM inspection, JS debugging/breakpoints, network traffic analysis, cookie security flags |

*(More rooms added as I progress through the path.)*

## 🎯 Why This Repo

I'm documenting each room as a proper mini-assessment writeup rather than just answering the room's questions — the goal is to build a portfolio that demonstrates methodology and communicates findings the way I would in a real pentest report, plus a reference I can come back to during interviews or on the job.

## 🛠️ Tools & Skills Covered So Far

- Browser DevTools (Inspector, Debugger/Sources, Network, Storage)
- Manual web application reconnaissance
- Client-side vs. server-side security control identification
- Cookie/session security analysis (HttpOnly, Secure, SameSite)

---

*Learning path: TryHackMe Jr Penetration Tester*
